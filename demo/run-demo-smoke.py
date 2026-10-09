#!/usr/bin/env python3
"""Driver for the demo Status List workflows.

From a clean checkout it creates an isolated environment, generates temporary
signing material, starts the Status List Server against in-memory storage, and
either runs the workflows headlessly or opens Jupyter Lab for interactive use.

Headless (default, used by CI):

  1. creates/uses the isolated demo environment (uv sync --locked),
  2. generates temporary signing material (self-signed cert + key),
  3. starts the Status List Server against in-memory storage,
  4. executes every workflow script in `./workflows` from a fresh state,
  5. stops the server and removes the temporary material even on failure.

Interactive (--interactive): steps 1-3, then opens Jupyter Lab rooted at the
demo directory so the workflow scripts can be stepped through by hand. The
server stays running for the whole session and is stopped when Jupyter exits.

Usage (from the `demo` directory):

    uv run python run-demo-smoke.py            # headless smoke check
    uv run python run-demo-smoke.py --interactive   # start server + Jupyter Lab

Environment:

    APP_SERVER__PORT   port to run the server on (default: a free port)

Exit code is non-zero if the server fails to start, any workflow script fails,
or cleanup itself fails. The owning workflow script is named in the failure
output. Logs are written under a temporary directory reported at startup.

On failure, the signing key and certificates are deliberately retained under the
log directory (defaulting to SMOKE_LOG_DIR) so the server and per-workflow logs
can be uploaded as CI artifacts. The key is a freshly generated, throwaway
self-signed demo key and is never committed.
"""

from __future__ import annotations

import argparse
import dataclasses
import os
import pathlib
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from typing import TextIO

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
DEMO_DIR = REPO_ROOT / "demo"
WORKFLOWS_DIR = DEMO_DIR / "workflows"
CERT_SCRIPT = DEMO_DIR / "generate-dev-cert.py"

WORKFLOWS = [
    "01-an-issuer-maintains-a-status-list.py",
    "02-issuers-can-maintain-multiple-status-lists.py",
    "03-issuer-b-cannot-update-issuer-a-list.py",
    "04-unregistered-issuers-cannot-publish-lists.py",
]

SERVER_START_TIMEOUT_SECONDS = 120
HEALTH_POLL_INTERVAL_SECONDS = 1
WORKFLOW_TIMEOUT_SECONDS = 120
# If the port was auto-selected, a stale free port can race with another process
# (find_free_port releases the port before the server binds it). Bound the retries
# so a transient AddressInUse turns into a healthy run instead of a flake.
SERVER_START_RETRIES = 3

# The server rate-limits credential registration and status-list writes per client
# IP. Each of the four workflow scripts makes a bounded number of such requests
# (roughly 6-9 each, ~28 in total). A burst of 100 gives a generous safety margin
# over that volume so a full run cannot trip the limiter, while still being small
# enough that a runaway loop fails the smoke check instead of hammering the server.
# If a future workflow adds many more requests, raise this constant and add a note
# here explaining the new volume.
STRICT_BURST_SIZE = 100


def log(message: str) -> None:
    print(f"[smoke] {message}", flush=True)


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def run(command: list[str], *, cwd: pathlib.Path, env: dict[str, str], timeout: int) -> subprocess.CompletedProcess:
    return subprocess.run(
        command,
        cwd=cwd,
        env=env,
        timeout=timeout,
        text=True,
        capture_output=True,
    )


def wait_for_health(base_url: str, timeout: int, server: ServerProcess) -> bool:
    import urllib.error
    import urllib.request

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        # If the server process has already exited (e.g. a startup failure such
        # as a compile error or a certificate/key mismatch), fail fast instead of
        # polling for the full timeout. The caller reports the server log.
        if server.proc.poll() is not None:
            return False
        try:
            with urllib.request.urlopen(f"{base_url}/health", timeout=2) as resp:
                if resp.status == 200 and resp.read().decode().strip() == "OK":
                    return True
        except (urllib.error.URLError, ConnectionError, OSError):
            pass
        time.sleep(HEALTH_POLL_INTERVAL_SECONDS)
    return False


def sync_environment() -> None:
    log("syncing the isolated demo environment (uv sync --locked)")
    result = run(
        ["uv", "sync", "--locked"],
        cwd=DEMO_DIR,
        env=os.environ.copy(),
        timeout=SERVER_START_TIMEOUT_SECONDS,
    )
    if result.returncode != 0:
        raise RuntimeError("uv sync --locked failed:\n" + result.stdout + result.stderr)


def generate_signing_material(out_dir: pathlib.Path) -> None:
    log(f"generating temporary signing material in {out_dir}")
    result = run(
        ["uv", "run", "python", str(CERT_SCRIPT), "--out-dir", str(out_dir), "--force"],
        cwd=DEMO_DIR,
        env=os.environ.copy(),
        timeout=60,
    )
    if result.returncode != 0:
        raise RuntimeError("generate-dev-cert.py failed:\n" + result.stdout + result.stderr)
    if not (out_dir / "tls.crt").exists() or not (out_dir / "tls.key").exists():
        raise RuntimeError("signing material was not produced by generate-dev-cert.py")


@dataclasses.dataclass
class ServerProcess:
    """A running server process and the log file its output is written to.

    ``cargo run`` spawns the actual server binary as a child process, so
    terminating the ``cargo`` process alone can leave the server orphaned and
    still holding its port. On POSIX we therefore start the server in its own
    process group and signal the whole group; on Windows we signal the process
    directly.
    """

    proc: subprocess.Popen
    log_file: TextIO


def start_server(port: int, signing_dir: pathlib.Path, log_dir: pathlib.Path) -> ServerProcess:
    env = os.environ.copy()
    env.update(
        {
            "APP_SERVER__PORT": str(port),
            "APP_SERVER__CERT__STORE__CERTIFICATE_PATH": str(signing_dir / "tls.crt"),
            "APP_SERVER__CERT__STORE__SIGNING_KEY_PATH": str(signing_dir / "tls.key"),
            "APP_RATE_LIMIT__STRICT_BURST_SIZE": str(STRICT_BURST_SIZE),
        }
    )
    log_file = open(log_dir / "server.log", "w")
    log(f"starting Status List Server on port {port}")
    proc = subprocess.Popen(
        ["cargo", "run", "--quiet", "--manifest-path", str(REPO_ROOT / "Cargo.toml")],
        cwd=REPO_ROOT,
        env=env,
        stdout=log_file,
        stderr=subprocess.STDOUT,
        # Put the cargo process (and the server it spawns) in their own process
        # group so we can signal the whole tree on cleanup instead of leaving an
        # orphaned server behind. A new session has no controlling terminal,
        # which is fine here: the server only needs stdout/stderr, not a TTY.
        start_new_session=os.name != "nt",
    )
    return ServerProcess(proc=proc, log_file=log_file)


def _signal_server_process_group(server: ServerProcess, sig: signal.Signals) -> None:
    """Send ``sig`` to the server's process group (or the process itself on Windows)."""
    if os.name == "nt":
        server.proc.send_signal(sig)
    else:
        # The process group can already be gone if the server exited between the
        # poll() check in stop_server and this call. Treat that as already-stopped
        # rather than letting the race surface as a ProcessLookupError.
        try:
            os.killpg(os.getpgid(server.proc.pid), sig)
        except ProcessLookupError:
            pass


def stop_server(server: ServerProcess) -> None:
    if server.proc.poll() is None:
        _signal_server_process_group(server, signal.SIGTERM)
        try:
            server.proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            _signal_server_process_group(server, signal.SIGKILL)
            server.proc.wait(timeout=10)
    server.log_file.close()


def start_server_and_wait_for_health(
    signing_dir: pathlib.Path, log_dir: pathlib.Path, *, requested_port: int | None
) -> tuple[ServerProcess, int]:
    """Start the server and wait for it to become healthy.

    When ``requested_port`` is None the port is auto-selected. ``find_free_port``
    releases the port it probes before the server binds it, so a concurrent
    process can take it in between (a TOCTOU race). In that case startup fails;
    retry with a fresh free port so the flake becomes a healthy run. A caller-pinned
    port is never retried with a different one, because the caller chose it.

    Returns the healthy server and the port it is bound to. Raises if no attempt
    succeeds.
    """
    attempts = SERVER_START_RETRIES if requested_port is None else 1
    last_port = requested_port
    for attempt in range(1, attempts + 1):
        port = requested_port if requested_port is not None else find_free_port()
        last_port = port
        base_url = f"http://localhost:{port}"
        server = start_server(port, signing_dir, log_dir)
        if wait_for_health(base_url, SERVER_START_TIMEOUT_SECONDS, server):
            return server, port
        log(f"server did not become healthy on port {port}; stopping and retrying")
        stop_server(server)
    raise RuntimeError(f"server failed to start on any of {attempts} port(s); last tried port {last_port}")


def run_workflows(port: int, log_dir: pathlib.Path) -> None:
    env = os.environ.copy()
    env["APP_SERVER__PORT"] = str(port)
    for workflow in WORKFLOWS:
        log(f"running workflow {workflow}")
        out_file = log_dir / (workflow.removesuffix(".py") + ".log")
        try:
            result = run(
                ["uv", "run", "python", workflow],
                cwd=WORKFLOWS_DIR,
                env=env,
                timeout=WORKFLOW_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired as exc:
            # Persist whatever the workflow produced before it was killed so the
            # timed-out run leaves an inspectable log identifying the owning cell.
            # exc.stdout/stderr are str when run() uses text=True; coerce bytes
            # defensively in case that ever changes.
            def _text(chunk):
                return chunk.decode(errors="replace") if isinstance(chunk, bytes) else (chunk or "")

            partial = _text(exc.stdout) + "\n" + _text(exc.stderr)
            with open(out_file, "w") as handle:
                handle.write(partial)
            print(
                f"::error::workflow timed out after {WORKFLOW_TIMEOUT_SECONDS}s: {workflow} "
                f"(see {out_file})",
                file=sys.stderr,
            )
            raise
        with open(out_file, "w") as handle:
            handle.write(result.stdout)
            handle.write(result.stderr)
        if result.returncode != 0:
            print(f"::error::workflow FAILED: {workflow} (see {out_file})", file=sys.stderr)
            print(result.stdout[-4000:] if result.stdout else "")
            print(result.stderr[-4000:] if result.stderr else "")
            raise RuntimeError(f"workflow {workflow} failed with exit code {result.returncode}")
        log(f"workflow {workflow} passed")


def run_interactive(
    requested_port: int | None,
    log_root: pathlib.Path,
    log_dir: pathlib.Path,
    signing_dir: pathlib.Path,
) -> int:
    """Start the server and open Jupyter Lab for interactive use.

    Keeps the server running for the whole Jupyter session and stops it (and
    removes the temporary material) when Jupyter exits.
    """
    server = None
    try:
        sync_environment()
        generate_signing_material(signing_dir)
        server, port = start_server_and_wait_for_health(
            signing_dir, log_dir, requested_port=requested_port
        )
        base_url = f"http://localhost:{port}"
        log(f"server is healthy on {base_url}")
        log("opening Jupyter Lab (workflow scripts live in ./workflows)")

        env = os.environ.copy()
        # Workflow scripts resolve the base URL from APP_SERVER__PORT.
        env["APP_SERVER__PORT"] = str(port)
        jupyter = subprocess.run(
            ["uv", "run", "jupyter", "lab", "--no-browser", "--port", "8888"],
            cwd=DEMO_DIR,
            env=env,
        )
        log(f"Jupyter Lab exited with code {jupyter.returncode}")
        return jupyter.returncode
    finally:
        if server is not None:
            stop_server(server)
        shutil.rmtree(log_root, ignore_errors=True)
        log("stopped server and removed temporary material")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="port for the server (default: a free port, or APP_SERVER__PORT if set)",
    )
    parser.add_argument(
        "--interactive",
        action="store_true",
        help="start the server and open Jupyter Lab instead of running the workflows headlessly",
    )
    args = parser.parse_args()

    # Resolve the requested port and temporary-artifact directories inside a guard so a
    # bad APP_SERVER__PORT or a filesystem error is reported cleanly instead of
    # escaping as an uncaught traceback.
    try:
        # A caller-pinned port (--port or APP_SERVER__PORT) is used as-is; otherwise the
        # port is auto-selected per attempt, so a stale free port is retried with a fresh
        # one instead of failing the run.
        requested_port = args.port or (
            int(os.environ["APP_SERVER__PORT"]) if os.environ.get("APP_SERVER__PORT") else None
        )

        # CI points SMOKE_LOG_DIR at a workspace-relative path so failure logs can be
        # uploaded as artifacts. Locally it is unset and logs live under a temp dir.
        smoke_log_dir = os.environ.get("SMOKE_LOG_DIR")
        log_root = pathlib.Path(smoke_log_dir) if smoke_log_dir else None
        if log_root is None:
            log_root = pathlib.Path(tempfile.mkdtemp(prefix="status-list-demo-smoke-"))
            log_root.mkdir(parents=True, exist_ok=True)
        log_dir = log_root / "logs"
        signing_dir = log_root / "signing"
        log_dir.mkdir(parents=True, exist_ok=True)
        signing_dir.mkdir(parents=True, exist_ok=True)
        log(f"temporary artifacts: {log_root}")
    except Exception as exc:  # noqa: BLE001
        print(f"::error::{exc}", file=sys.stderr)
        return 1

    # Interactive mode manages its own server lifetime and cleanup.
    if args.interactive:
        return run_interactive(requested_port, log_root, log_dir, signing_dir)

    server_proc = None
    success = False
    try:
        sync_environment()
        generate_signing_material(signing_dir)
        server_proc, port = start_server_and_wait_for_health(
            signing_dir, log_dir, requested_port=requested_port
        )
        base_url = f"http://localhost:{port}"

        log(f"server is healthy on {base_url}")
        run_workflows(port, log_dir)
        log("all workflows passed")
        success = True
        return 0
    except Exception as exc:  # noqa: BLE001 - driver must always clean up and report
        print(f"::error::{exc}", file=sys.stderr)
        return 1
    finally:
        if server_proc is not None:
            stop_server(server_proc)
        if success:
            shutil.rmtree(log_root, ignore_errors=True)
            log("cleaned up temporary material")
        else:
            # Keep logs and signing material for CI artifact upload on failure.
            log(f"FAILURE: logs retained at {log_root}")


if __name__ == "__main__":
    sys.exit(main())
