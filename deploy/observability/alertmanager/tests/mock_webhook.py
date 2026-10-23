#!/usr/bin/env python3
"""Mock webhook for test-alertmanager-config.sh: appends each POST to a JSON-lines file."""

import argparse
import fcntl
import json
import signal
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=18080)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    count = 0
    count_lock = threading.Lock()

    def record(payload: dict) -> None:
        nonlocal count
        with count_lock:
            with open(args.out, "a") as f:
                fcntl.flock(f, fcntl.LOCK_EX)
                f.write(json.dumps(payload) + "\n")
                f.flush()
                fcntl.flock(f, fcntl.LOCK_UN)
            count += 1

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
            try:
                payload = json.loads(body.decode("utf-8"))
            except Exception:
                payload = {"raw": body.decode("utf-8", "replace")}
            record(payload)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b"{}")

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    stop = threading.Event()

    def shutdown(signum, frame):
        stop.set()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    print(f"mock_webhook listening on 127.0.0.1:{args.port} -> {args.out}",
          flush=True)

    while not stop.wait(0.25):
        pass

    server.shutdown()
    server.server_close()
    print(f"mock_webhook received {count} notification(s)")
    return 0 if count else 1


if __name__ == "__main__":
    sys.exit(main())
