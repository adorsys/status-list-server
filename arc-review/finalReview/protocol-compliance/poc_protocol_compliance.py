#!/usr/bin/env python3
"""Reproduce protocol-compliance failures through the public HTTP API.

The ``poc_N_*`` function names match the PoC IDs in README.md.
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


ALLOWED_BITS = {1, 2, 4, 8}


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
        self.issuer = f"poc-protocol-{uuid.uuid4()}"
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
        header = {"alg": "ES256", "typ": "unrelated+jwt"}
        claims = {"iss": self.issuer, "exp": int(time.time()) + 3600}
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


def decode_jwt(headers: dict[str, str], body: bytes) -> tuple[dict, dict]:
    if headers.get("content-encoding", "").lower() == "gzip" or body.startswith(b"\x1f\x8b"):
        body = gzip.decompress(body)
    parts = body.decode("utf-8").split(".")
    if len(parts) != 3:
        raise PocError("status response is not a compact JWT")
    return json.loads(b64url_decode(parts[0])), json.loads(b64url_decode(parts[1]))


def decode_status(raw: bytes, bits: int, index: int) -> int:
    value = 0
    for bit in range(bits):
        position = index * bits + bit
        if position // 8 >= len(raw):
            raise PocError(f"status index {index} exceeds the decoded list")
        value |= ((raw[position // 8] >> (position % 8)) & 1) << bit
    return value


def publish(base_url: str, token: str, statuses: list[dict]) -> str:
    list_id = str(uuid.uuid4())
    status, _, body = http_request(
        "PUT",
        f"{base_url}/api/v1/status-lists/{list_id}/statuses",
        {"statuses": statuses},
        {"Authorization": f"Bearer {token}"},
    )
    require_status(status, 201, "status-list publication", body)
    return list_id


def fetch_jwt(base_url: str, list_id: str) -> tuple[dict, dict, dict[str, str]]:
    status, headers, body = http_request(
        "GET",
        f"{base_url}/api/v1/status-lists/{list_id}",
        headers={"Accept": "application/statuslist+jwt"},
    )
    require_status(status, 200, "JWT status-list GET", body)
    jwt_header, claims = decode_jwt(headers, body)
    return jwt_header, claims, headers


def poc_1_minimal_management_token(base_url: str, token: str) -> None:
    """PoC 1: application profile outside draft-21.

    Basis: https://www.rfc-editor.org/rfc/rfc8725.html#section-3.12
    """
    publish(base_url, token, [{"index": 0, "status": 0}])
    print("[1/7] Minimal management token accepted: HTTP 201")


def poc_2_unsupported_bit_width(base_url: str, token: str) -> None:
    """PoC 2: draft-21 forbids status value 256 and bits=9.

    Basis: https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-21.html#section-4.1
    Basis: https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-21.html#section-7
    """
    list_id = publish(base_url, token, [{"index": 0, "status": 256}])
    _, claims, _ = fetch_jwt(base_url, list_id)
    status_list = claims["status_list"]
    bits = int(status_list["bits"])
    if bits in ALLOWED_BITS:
        raise PocError(f"expected an unsupported width, observed bits={bits}")
    zlib.decompress(b64url_decode(status_list["lst"]))
    print(f"[2/7] Unsupported status representation: bits={bits} (allowed: 1,2,4,8)")


def poc_3_empty_non_zlib_list(base_url: str, token: str) -> None:
    """PoC 3: draft-21 requires a ZLIB-compressed byte array.

    Basis: https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-21.html#section-4.1
    """
    list_id = publish(base_url, token, [])
    _, claims, _ = fetch_jwt(base_url, list_id)
    empty_lst = claims["status_list"]["lst"]
    try:
        zlib.decompress(b64url_decode(empty_lst))
    except zlib.error:
        empty_decode_failed = True
    else:
        empty_decode_failed = False
    if empty_lst != "" or not empty_decode_failed:
        raise PocError("expected empty lst to fail independent ZLIB decoding")
    print('[3/7] Empty status representation: lst=""; ZLIB decode failed')


def poc_4_duplicate_index(base_url: str, token: str) -> None:
    """PoC 4: management witness, not proof of double allocation.

    Basis: https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-21.html#section-13.3
    """
    list_id = publish(
        base_url,
        token,
        [{"index": 0, "status": 1}, {"index": 0, "status": 2}],
    )
    _, claims, _ = fetch_jwt(base_url, list_id)
    status_list = claims["status_list"]
    raw = zlib.decompress(b64url_decode(status_list["lst"]))
    final_status = decode_status(raw, int(status_list["bits"]), 0)
    if final_status != 2:
        raise PocError(f"expected duplicate last-write-wins value 2, observed {final_status}")
    print("[4/7] Duplicate index accepted: final status[0]=2 (last write wins)")


def poc_5_expired_jwt_revalidation(base_url: str, token: str) -> None:
    """PoC 5: an expired retained JWT receives HTTP 304.

    Basis: https://www.rfc-editor.org/rfc/rfc9110.html#section-8.8.1
    Basis: https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-21.html#section-8.2
    """
    list_id = publish(base_url, token, [{"index": 0, "status": 0}])
    _, claims, headers = fetch_jwt(base_url, list_id)
    expiration = int(claims["exp"])
    time.sleep(max(0.0, expiration - time.time() + 0.25))
    status, _, body = http_request(
        "GET",
        f"{base_url}/api/v1/status-lists/{list_id}",
        headers={
            "Accept": "application/statuslist+jwt",
            "If-None-Match": headers["etag"],
        },
    )
    if status != 304 or body:
        raise PocError(
            "expected an expired representation to receive HTTP 304 with no replacement body"
        )
    if int(time.time()) < expiration:
        raise PocError("clock did not advance to the JWT expiration")
    print("[5/7] Expired JWT revalidation: HTTP 304 with no replacement body")


def poc_6_non_acme_certificate_encoding(base_url: str, token: str) -> None:
    """PoC 6: non-ACME x5c encoding and CWT issuance failure.

    Basis: https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.6
    Basis: https://www.rfc-editor.org/rfc/rfc9360.html#section-2
    """
    list_id = publish(base_url, token, [{"index": 0, "status": 0}])
    jwt_header, _, _ = fetch_jwt(base_url, list_id)
    x5c = jwt_header.get("x5c") or []
    pem_in_x5c = bool(x5c and x5c[0].lstrip().startswith("-----BEGIN CERTIFICATE-----"))
    cwt_status, _, _ = http_request(
        "GET",
        f"{base_url}/api/v1/status-lists/{list_id}",
        headers={"Accept": "application/statuslist+cwt"},
    )
    if not pem_in_x5c or cwt_status < 500:
        raise PocError(
            f"expected PEM in JWT x5c and CWT server failure, observed CWT HTTP {cwt_status}"
        )
    print(f"[6/7] Non-ACME certificate path: JWT x5c contains PEM; CWT HTTP {cwt_status}")


def poc_7_historical_token_issued_at(base_url: str, token: str) -> None:
    """PoC 7: a historical response is signed now but reports the snapshot iat.

    Basis: https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-21.html#section-5.1
    Basis: https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-21.html#section-8.4
    """
    list_id = publish(base_url, token, [{"index": 0, "status": 0}])

    # Keep the request inside the snapshot's four-second validity window while
    # ensuring the new signature happens in a later Unix second.
    time.sleep(1.1)
    server_now_candidate = int(time.time())
    response: tuple[int, dict[str, str], bytes] | None = None
    historical_time = 0
    for offset in range(5):
        historical_time = server_now_candidate - offset
        response = http_request(
            "GET",
            f"{base_url}/api/v1/status-lists/{list_id}?time={historical_time}",
            headers={"Accept": "application/statuslist+jwt"},
        )
        if response[0] == 200:
            break
        if response[0] not in {400, 404}:
            require_status(response[0], 200, "historical JWT status-list GET", response[2])
    else:
        raise PocError("no recent timestamp produced a historical JWT response")

    assert response is not None
    status, headers, body = response
    require_status(status, 200, "historical JWT status-list GET", body)
    _, claims = decode_jwt(headers, body)
    issued_at = int(claims["iat"])

    if issued_at >= historical_time:
        raise PocError(
            "expected historical JWT to retain an iat older than the accepted request time"
        )
    print(
        "[7/7] Historical JWT uses snapshot iat: "
        f"iat={issued_at}; historical_time={historical_time}"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:18003")
    parser.add_argument(
        "--confirm-disposable-target",
        action="store_true",
        help="required acknowledgement that the target is non-production and disposable",
    )
    args = parser.parse_args()
    if not args.confirm_disposable_target:
        parser.error("--confirm-disposable-target is required")
    base_url = require_loopback_url(args.base_url)

    health, _, body = http_request("GET", f"{base_url}/health")
    require_status(health, 200, "health check", body)

    with tempfile.TemporaryDirectory(prefix="status-list-protocol-poc-") as temp_dir:
        issuer = EphemeralIssuer(Path(temp_dir))
        status, _, body = http_request(
            "POST",
            f"{base_url}/api/v1/credentials",
            {"issuer": issuer.issuer, "public_key": issuer.jwk},
        )
        require_status(status, 202, "credential registration", body)
        token = issuer.management_token()

        poc_1_minimal_management_token(base_url, token)
        poc_2_unsupported_bit_width(base_url, token)
        poc_3_empty_non_zlib_list(base_url, token)
        poc_4_duplicate_index(base_url, token)
        poc_5_expired_jwt_revalidation(base_url, token)
        poc_6_non_acme_certificate_encoding(base_url, token)
        poc_7_historical_token_issued_at(base_url, token)

    print("\nRESULT: documented protocol and assurance findings reproduced")


if __name__ == "__main__":
    try:
        main()
    except (OSError, PocError, subprocess.SubprocessError) as error:
        raise SystemExit(f"PoC failed: {error}") from error
