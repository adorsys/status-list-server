"""Unit tests for the demo smoke driver's pure helpers.

The driver (``run-demo-smoke.py``) is a CLI script, so it is loaded as a module
here to exercise its helpers without starting a server. External side effects
(subprocess calls, sockets) are mocked.
"""

import importlib.util
import pathlib
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

DEMO_DIR = pathlib.Path(__file__).resolve().parents[1]
DRIVER_PATH = DEMO_DIR / "run-demo-smoke.py"


def load_driver():
    spec = importlib.util.spec_from_file_location("run_demo_smoke", DRIVER_PATH)
    module = importlib.util.module_from_spec(spec)
    # Register before exec so the module's dataclass resolution works.
    sys.modules["run_demo_smoke"] = module
    spec.loader.exec_module(module)
    return module


class FindFreePortTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.driver = load_driver()

    def test_returns_a_port_we_can_bind(self):
        port = self.driver.find_free_port()
        self.assertIsInstance(port, int)
        self.assertTrue(1 <= port <= 65535)
        # The returned port must be bindable on localhost.
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", port))


class StartServerEnvTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.driver = load_driver()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.dir = pathlib.Path(self.temp.name)
        self.signing = self.dir / "signing"
        self.logs = self.dir / "logs"
        self.signing.mkdir()
        self.logs.mkdir()

    @mock.patch.object(subprocess, "Popen")
    def test_sets_port_cert_and_burst_size_env(self, popen):
        popen.return_value.poll.return_value = None
        server = self.driver.start_server(12345, self.signing, self.logs)
        self.addCleanup(server.log_file.close)
        env = popen.call_args.kwargs["env"]
        self.assertEqual(env["APP_SERVER__PORT"], "12345")
        self.assertEqual(
            env["APP_SERVER__CERT__STORE__CERTIFICATE_PATH"],
            str(self.signing / "tls.crt"),
        )
        self.assertEqual(
            env["APP_SERVER__CERT__STORE__SIGNING_KEY_PATH"],
            str(self.signing / "tls.key"),
        )
        self.assertEqual(
            env["APP_RATE_LIMIT__STRICT_BURST_SIZE"],
            str(self.driver.STRICT_BURST_SIZE),
        )

    @mock.patch.object(subprocess, "Popen")
    def test_writes_server_output_to_server_log(self, popen):
        popen.return_value.poll.return_value = None
        server = self.driver.start_server(12346, self.signing, self.logs)
        self.addCleanup(server.log_file.close)
        self.assertTrue((self.logs / "server.log").exists())


class RunWorkflowsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.driver = load_driver()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.dir = pathlib.Path(self.temp.name)

    @mock.patch.object(subprocess, "run")
    def test_sets_the_workflow_port_from_the_integer_argument(self, run):
        # A completed process for each workflow.
        run.return_value = subprocess.CompletedProcess([], 0, stdout="ok", stderr="")
        self.driver.run_workflows(4321, self.dir)
        for call in run.call_args_list:
            self.assertEqual(call.kwargs["env"]["APP_SERVER__PORT"], "4321")

    @mock.patch.object(subprocess, "run")
    def test_writes_a_log_per_workflow(self, run):
        run.return_value = subprocess.CompletedProcess([], 0, stdout="out", stderr="err")
        self.driver.run_workflows(4322, self.dir)
        for workflow in self.driver.WORKFLOWS:
            log = self.dir / (workflow.removesuffix(".py") + ".log")
            self.assertTrue(log.exists(), f"missing log {log}")
            self.assertIn("out", log.read_text())

    @mock.patch.object(subprocess, "run")
    def test_raises_when_a_workflow_fails(self, run):
        run.return_value = subprocess.CompletedProcess([], 1, stdout="boom", stderr="")
        with self.assertRaisesRegex(RuntimeError, "workflow .* failed"):
            self.driver.run_workflows(4323, self.dir)

    @mock.patch.object(subprocess, "run")
    def test_timeout_writes_partial_output_then_reraises(self, run):
        run.side_effect = subprocess.TimeoutExpired(
            ["uv", "run", "python", "x"], 1, output=b"partial stdout", stderr=b"partial stderr"
        )
        with self.assertRaises(subprocess.TimeoutExpired):
            self.driver.run_workflows(4324, self.dir)
        first = self.driver.WORKFLOWS[0]
        log = self.dir / (first.removesuffix(".py") + ".log")
        self.assertTrue(log.exists(), "expected a log even on timeout")
        content = log.read_text()
        self.assertIn("partial stdout", content)
        self.assertIn("partial stderr", content)


class WaitForHealthTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.driver = load_driver()

    def test_returns_false_immediately_when_server_process_exited(self):
        # A process whose poll() is non-None has already exited; the health loop
        # must fail fast instead of polling (and trying to open a socket).
        proc = mock.Mock()
        proc.poll.return_value = 1
        server = self.driver.ServerProcess(proc=proc, log_file=mock.Mock())
        result = self.driver.wait_for_health("http://localhost:1", timeout=60, server=server)
        self.assertFalse(result)


if __name__ == "__main__":
    unittest.main()
