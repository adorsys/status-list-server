import contextlib
import importlib.util
import io
from pathlib import Path
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

spec = importlib.util.spec_from_file_location(
    'sandbox_scan', Path(__file__).with_name('check-hosted-sandbox.py'))
scan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scan)


class SandboxScanTests(unittest.TestCase):
    def run_scan(self, override=None, separate=False):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.respond()

            do_POST = do_PUT = do_PATCH = do_GET

            def log_message(self, *args):
                pass

            def respond(self):
                management = not separate or self.server is servers[-1]
                status = 404
                body = b'{}'
                if self.path == '/health/live':
                    status = 200
                elif management and self.path.startswith('/api/v1/'):
                    status = 401
                    body = b'{"error":"missing_token"}'
                if override:
                    status, body = override(self, status, body)
                self.send_response(status)
                if status == 302:
                    self.send_header('Location', '/health/live')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        servers = [ThreadingHTTPServer(('127.0.0.1', 0), Handler)
                   for _ in range(2 if separate else 1)]
        threads = [threading.Thread(target=s.serve_forever, daemon=True) for s in servers]
        for thread in threads:
            thread.start()
        args = [f'http://127.0.0.1:{servers[0].server_port}']
        if separate:
            args += ['--management-hostname', f'http://127.0.0.1:{servers[-1].server_port}']
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                return scan.main(args)
        finally:
            for server in servers:
                server.shutdown()
                server.server_close()
            for thread in threads:
                thread.join()

    def test_shared_and_separate_hosts(self):
        self.assertEqual(self.run_scan(), 0)
        self.assertEqual(self.run_scan(separate=True), 0)

    def test_exposed_admin_is_rejected_even_with_auth(self):
        for status in (200, 401, 403):
            with self.subTest(status=status):
                self.assertEqual(self.run_scan(
                    lambda r, s, b: (status, b) if r.path == '/admin/v1/issuers' else (s, b)), 1)

    def test_anonymous_write_and_missing_management_route_fail(self):
        for status in (200, 404):
            with self.subTest(status=status):
                self.assertEqual(self.run_scan(
                    lambda r, s, b: (status, b) if r.command == 'PUT' else (s, b)), 1)

    def test_redirect_and_non_api_auth_response_fail(self):
        self.assertEqual(self.run_scan(
            lambda r, s, b: (302, b) if r.path == '/metrics' else (s, b)), 1)
        self.assertEqual(self.run_scan(
            lambda r, s, b: (s, b'<html>login</html>') if s == 401 else (s, b)), 1)

    def test_connection_failure(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertFalse(scan.probe(scan.urllib.request.build_opener(),
                                        'http://127.0.0.1:0', 'GET', '/', 200))

    def test_origin_rejects_credentials_paths_and_unsupported_schemes(self):
        self.assertEqual(scan.origin('sandbox.example.org'), 'https://sandbox.example.org')
        for value in ('https://user:password@example.org', 'https://example.org/path',
                      'ftp://example.org', 'https://example.org/?query=1'):
            with self.subTest(value=value):
                with self.assertRaises(scan.argparse.ArgumentTypeError):
                    scan.origin(value)


if __name__ == '__main__':
    unittest.main()
