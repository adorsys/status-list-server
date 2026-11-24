#!/usr/bin/env python3
"""Check the published sandbox surface without credentials or valid write bodies."""

import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request


class NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def origin(value):
    parsed = urllib.parse.urlsplit(value if "://" in value else "https://" + value)
    if (
        parsed.scheme not in ("http", "https")
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        raise argparse.ArgumentTypeError("provide a hostname or an HTTP(S) origin")
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))


def probe(opener, base, method, path, expected, error=None):
    body = b"{}" if method in ("POST", "PUT", "PATCH") else None
    request = urllib.request.Request(
        base + path, data=body, method=method,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    try:
        response = opener.open(request, timeout=10)
    except urllib.error.HTTPError as response_error:
        response = response_error
    except (urllib.error.URLError, OSError):
        print(f"FAIL {method} {base}{path}: connection or TLS failure")
        return False
    with response:
        passed = response.code in expected if isinstance(expected, tuple) else response.code == expected
        if passed and error and response.code == 401:
            try:
                passed = json.loads(response.read(16384)).get("error") == error
            except (ValueError, AttributeError):
                passed = False
        print(f"{'PASS' if passed else 'FAIL'} {method} {base}{path}: HTTP {response.code}")
        return passed


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("hostname", type=origin)
    parser.add_argument("--management-hostname", type=origin)
    args = parser.parse_args(argv)
    public = args.hostname
    management = args.management_hostname or public
    opener = urllib.request.build_opener(NoRedirects())
    checks = []
    checks.append(probe(opener, public, "GET", "/health/live", 200))
    for base in dict.fromkeys((public, management)):
        for path in ("/metrics", "/health/ready", "/admin/v1/issuers",
                     "/admin/v1/issuers/00000000-0000-4000-8000-000000000000"):
            checks.append(probe(opener, base, "GET", path, 404))
        admin_issuer = "/admin/v1/issuers/00000000-0000-4000-8000-000000000000"
        for method, path in (
            ("POST", "/admin/v1/issuers"),
            ("POST", admin_issuer + "/keys"),
            ("PATCH", admin_issuer),
            ("PATCH", admin_issuer + "/keys/00000000-0000-4000-8000-000000000001"),
        ):
            checks.append(probe(opener, base, method, path, 404))
        list_path = "/api/v1/status-lists/00000000-0000-4000-8000-000000000000"
        expected = 401 if base == management else 404
        for method, path in (
            ("PUT", list_path + "/statuses"),
            ("PATCH", list_path + "/statuses"),
            ("POST", list_path + "/allocations"),
            ("GET", "/api/v1/credentials"),
        ):
            checks.append(probe(opener, base, method, path, expected,
                                "missing_token" if expected == 401 else None))
        checks.append(probe(opener, base, "POST", "/api/v1/credentials", (401, 405) if base == management else 404,
                            "missing_token" if base == management else None))
    return 0 if all(checks) else 1


if __name__ == "__main__":
    sys.exit(main())
