#!/usr/bin/env python3
"""Demonstrate stale signed status data across two application pods.

Both URLs must address individual pods that share one SQL database. The script
creates synthetic data, warms pod A's local cache, updates through pod B, and
then compares the signed responses returned by both pods.
"""

import argparse
import base64
import gzip
import json
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils


VALID = 0
INVALID = 1


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
    request_headers = {}
    if body is not None:
        request_headers["Content-Type"] = "application/json"
    if headers:
        request_headers.update(headers)

    request = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers=request_headers,
    )
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
        raise PocError(
            f"{operation} returned HTTP {actual}, expected {expected}: {detail}"
        )


def require_loopback_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise PocError(f"refusing non-loopback or non-HTTP target: {url}")
    return url.rstrip("/")


def generate_issuer() -> tuple[str, ec.EllipticCurvePrivateKey, dict]:
    issuer = f"poc-multi-pod-{uuid.uuid4()}"
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_numbers = private_key.public_key().public_numbers()
    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": b64url_encode(public_numbers.x.to_bytes(32, "big")),
        "y": b64url_encode(public_numbers.y.to_bytes(32, "big")),
    }
    return issuer, private_key, jwk


def sign_management_token(private_key: ec.EllipticCurvePrivateKey, issuer: str) -> str:
    header = {"alg": "ES256", "typ": "JWT"}
    now = int(time.time())
    claims = {"iss": issuer, "iat": now, "exp": now + 3600}
    signing_input = ".".join(
        [
            b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8")),
            b64url_encode(json.dumps(claims, separators=(",", ":")).encode("utf-8")),
        ]
    ).encode("ascii")
    der_signature = private_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(der_signature)
    signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return signing_input.decode("ascii") + "." + b64url_encode(signature)


def decode_status_response(headers: dict[str, str], body: bytes, index: int) -> dict:
    if headers.get("content-encoding", "").lower() == "gzip" or body.startswith(
        b"\x1f\x8b"
    ):
        body = gzip.decompress(body)

    token = body.decode("utf-8")
    parts = token.split(".")
    if len(parts) != 3:
        raise PocError("status response is not a compact JWT")

    payload = json.loads(b64url_decode(parts[1]))
    status_list = payload["status_list"]
    bits = int(status_list["bits"])
    status_bytes = zlib.decompress(b64url_decode(status_list["lst"]))
    bit_position = index * bits
    byte_index = bit_position // 8
    if byte_index >= len(status_bytes):
        raise PocError(f"index {index} is outside the decoded status array")
    status = (status_bytes[byte_index] >> (bit_position % 8)) & ((1 << bits) - 1)
    return {
        "status": status,
        "iat": int(payload["iat"]),
        "etag": headers.get("etag", "<missing>"),
    }


def fetch_status(base_url: str, list_id: str, index: int) -> dict:
    status, headers, body = http_request(
        "GET",
        f"{base_url}/api/v1/status-lists/{list_id}",
        headers={"Accept": "application/statuslist+jwt"},
    )
    require_status(status, 200, f"GET from {base_url}", body)
    return decode_status_response(headers, body, index)


def format_observation(label: str, observation: dict) -> None:
    status_name = {VALID: "VALID", INVALID: "INVALID"}.get(
        observation["status"], str(observation["status"])
    )
    print(
        f"{label}: status[0]={status_name}({observation['status']}), "
        f"iat={observation['iat']}, ETag={observation['etag']}"
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Demonstrate cross-pod status-cache incoherence in an isolated environment."
    )
    parser.add_argument("--pod-a-url", default="http://127.0.0.1:18001")
    parser.add_argument("--pod-b-url", default="http://127.0.0.1:18002")
    parser.add_argument("--settle-seconds", type=float, default=1.1)
    parser.add_argument(
        "--confirm-disposable-target",
        action="store_true",
        help="required acknowledgement that the target is non-production and disposable",
    )
    args = parser.parse_args()

    if not args.confirm_disposable_target:
        parser.error("--confirm-disposable-target is required")

    pod_a = require_loopback_url(args.pod_a_url)
    pod_b = require_loopback_url(args.pod_b_url)
    if pod_a == pod_b:
        parser.error(
            "pod A and pod B URLs must address different application processes"
        )

    for label, base_url in (("pod A", pod_a), ("pod B", pod_b)):
        status, _, body = http_request("GET", f"{base_url}/health")
        require_status(status, 200, f"health check for {label}", body)

    issuer, private_key, jwk = generate_issuer()
    token = sign_management_token(private_key, issuer)
    list_id = str(uuid.uuid4())
    auth = {"Authorization": f"Bearer {token}"}

    print("Creating synthetic issuer and status list through pod B")
    status, _, body = http_request(
        "POST",
        f"{pod_b}/api/v1/credentials",
        {"issuer": issuer, "public_key": jwk},
    )
    require_status(status, 202, "credential registration", body)

    status, _, body = http_request(
        "PUT",
        f"{pod_b}/api/v1/status-lists/{list_id}/statuses",
        {"statuses": [{"index": 0, "status": VALID}]},
        auth,
    )
    require_status(status, 201, "status-list publication", body)

    print("Warming pod A's process-local cache with V1")
    before = fetch_status(pod_a, list_id, 0)
    format_observation("Pod A before PATCH", before)
    if before["status"] != VALID:
        raise PocError("new list did not start as VALID")

    time.sleep(args.settle_seconds)
    print("Committing V2 (INVALID) through pod B")
    status, _, body = http_request(
        "PATCH",
        f"{pod_b}/api/v1/status-lists/{list_id}/statuses",
        {"statuses": [{"index": 0, "status": INVALID}]},
        auth,
    )
    require_status(status, 200, "status update", body)

    writer_view = fetch_status(pod_b, list_id, 0)
    stale_view = fetch_status(pod_a, list_id, 0)
    format_observation("Pod B after PATCH ", writer_view)
    format_observation("Pod A after PATCH ", stale_view)

    issue_observed = (
        writer_view["status"] == INVALID
        and stale_view["status"] == VALID
        and writer_view["etag"] != stale_view["etag"]
        and stale_view["etag"] == before["etag"]
        and stale_view["iat"] > before["iat"]
    )

    print()
    if issue_observed:
        print("RESULT: multi-pod stale-cache issue reproduced")
        print(
            "Pod B committed and returned INVALID, while pod A re-signed cached VALID state."
        )
        return

    print("RESULT: the expected stale-cache signature was not observed")
    print(
        "The cache may be disabled, expired, coherent, or the implementation may be fixed."
    )
    raise SystemExit(2)


if __name__ == "__main__":
    try:
        main()
    except PocError as error:
        raise SystemExit(f"PoC failed: {error}") from error
