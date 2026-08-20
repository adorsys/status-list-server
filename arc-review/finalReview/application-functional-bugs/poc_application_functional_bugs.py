#!/usr/bin/env python3
"""Reproduce bounded functional failures against the disposable local stack.

The ``poc_N_*`` function names are the canonical PoC IDs used by README.md.
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
ALLOWED_BITS = {1, 2, 4, 8}
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


def wait_for_health(label: str, base_url: str, timeout: float = 120.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            status, _, _ = http_request("GET", f"{base_url}/health")
            if status == 200:
                return
        except PocError:
            pass
        time.sleep(1.0)
    raise PocError(f"{label} did not become healthy within {timeout:.0f} seconds")


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


def der_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def der_integer(raw: bytes) -> bytes:
    value = raw.lstrip(b"\x00") or b"\x00"
    if value[0] & 0x80:
        value = b"\x00" + value
    return b"\x02" + der_length(len(value)) + value


def ecdsa_raw_to_der(signature: bytes) -> bytes:
    if len(signature) != 64:
        raise PocError(f"expected a 64-byte ES256 signature, observed {len(signature)} bytes")
    sequence = der_integer(signature[:32]) + der_integer(signature[32:])
    return b"\x30" + der_length(len(sequence)) + sequence


class EphemeralIssuer:
    def __init__(self, directory: Path):
        self.issuer = f"poc-functional-{uuid.uuid4()}"
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
        now = int(time.time())
        claims = {"iss": self.issuer, "iat": now, "exp": now + 3600}
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


class StatusTokenVerifier:
    def __init__(self, signing_key_path: Path, directory: Path):
        self.public_key_path = directory / "status-token-public-key.pem"
        exported = subprocess.run(
            ["openssl", "pkey", "-in", str(signing_key_path), "-pubout"],
            capture_output=True,
            check=False,
        )
        if exported.returncode != 0:
            raise PocError(f"test signing-key parsing failed: {exported.stderr.decode().strip()}")
        self.public_key_path.write_bytes(exported.stdout)
        self.signature_path = directory / "status-token-signature.der"

    def decode_and_verify(self, headers: dict[str, str], body: bytes) -> tuple[dict, dict]:
        if headers.get("content-encoding", "").lower() == "gzip" or body.startswith(b"\x1f\x8b"):
            body = gzip.decompress(body)
        parts = body.decode("utf-8").split(".")
        if len(parts) != 3:
            raise PocError("status response is not a compact JWT")
        self.signature_path.write_bytes(ecdsa_raw_to_der(b64url_decode(parts[2])))
        verified = subprocess.run(
            [
                "openssl",
                "dgst",
                "-sha256",
                "-verify",
                str(self.public_key_path),
                "-signature",
                str(self.signature_path),
            ],
            input=f"{parts[0]}.{parts[1]}".encode("ascii"),
            capture_output=True,
            check=False,
        )
        if verified.returncode != 0:
            raise PocError(f"status-token signature verification failed: {verified.stderr.decode().strip()}")
        return json.loads(b64url_decode(parts[0])), json.loads(b64url_decode(parts[1]))


def publish(base_url: str, token: str, statuses: list[dict], list_id: str | None = None) -> str:
    list_id = list_id or str(uuid.uuid4())
    status, _, body = http_request(
        "PUT",
        f"{base_url}/api/v1/status-lists/{list_id}/statuses",
        {"statuses": statuses},
        {"Authorization": f"Bearer {token}"},
    )
    require_status(status, 201, "status-list publication", body)
    return list_id


def fetch_jwt(
    base_url: str,
    list_id: str,
    verifier: StatusTokenVerifier,
) -> tuple[dict, dict, dict[str, str]]:
    status, headers, body = http_request(
        "GET",
        f"{base_url}/api/v1/status-lists/{list_id}",
        headers={"Accept": "application/statuslist+jwt"},
    )
    require_status(status, 200, "JWT status-list GET", body)
    jwt_header, claims = verifier.decode_and_verify(headers, body)
    return jwt_header, claims, headers


def decode_status(claims: dict, index: int) -> int:
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


def database_state(compose_file: Path, project_name: str, list_id: str) -> tuple[int, int, int]:
    safe_list_id = str(uuid.UUID(list_id))
    sql = (
        "SELECT s.updated_at, count(h.snapshot_id), "
        "count(DISTINCT h.status_list::text) "
        "FROM status_lists s LEFT JOIN status_list_history h ON h.list_id = s.list_id "
        f"WHERE s.list_id = '{safe_list_id}' GROUP BY s.updated_at;"
    )
    queried = subprocess.run(
        [
            "docker",
            "compose",
            "-p",
            project_name,
            "-f",
            str(compose_file),
            "exec",
            "-T",
            "db",
            "psql",
            "-U",
            "postgres",
            "-d",
            "status-list",
            "-At",
            "-F",
            "|",
            "-c",
            sql,
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if queried.returncode != 0:
        raise PocError(f"disposable database query failed: {queried.stderr.strip()}")
    fields = queried.stdout.strip().split("|")
    if len(fields) != 3:
        raise PocError(f"unexpected disposable database result: {queried.stdout!r}")
    return tuple(int(field) for field in fields)


def poc_1_openapi_status_contract_mismatch(base_url: str, token: str) -> None:
    """PoC 1: the published request schema and runtime wire type disagree.

    Contract: https://github.com/adorsys/status-list-server/blob/adbe8fdacae5edb1ce655a14a5f5f2120ea229e3/docs/openapi.yaml#L481-L525
    """
    list_id = str(uuid.uuid4())
    auth = {"Authorization": f"Bearer {token}"}
    documented_status, _, documented_body = http_request(
        "PUT",
        f"{base_url}/api/v1/status-lists/{list_id}/statuses",
        {"statuses": [{"index": 0, "status": "VALID"}]},
        auth,
    )
    if documented_status < 400:
        raise PocError("documented string status was unexpectedly accepted")
    numeric_status, _, numeric_body = http_request(
        "PUT",
        f"{base_url}/api/v1/status-lists/{list_id}/statuses",
        {"statuses": [{"index": 0, "status": 0}]},
        auth,
    )
    require_status(numeric_status, 201, "undocumented numeric status publication", numeric_body)
    if not documented_body:
        raise PocError("documented string rejection had no error response")
    print(
        "[1/6] poc_1_openapi_status_contract_mismatch: "
        f'documented "VALID" -> HTTP {documented_status}; numeric 0 -> HTTP 201'
    )


def poc_2_invalid_signed_status_representation(
    base_url: str,
    token: str,
    verifier: StatusTokenVerifier,
) -> None:
    """PoC 2: signed bits=9 and empty non-ZLIB representations violate draft-21.

    Specification: https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-21.html#section-4.1
    Specification: https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-21.html#section-7
    """
    wide_id = publish(base_url, token, [{"index": 0, "status": 256}])
    _, wide_claims, _ = fetch_jwt(base_url, wide_id, verifier)
    wide_list = wide_claims["status_list"]
    bits = int(wide_list["bits"])
    if bits != 9 or bits in ALLOWED_BITS:
        raise PocError(f"expected unsupported bits=9, observed bits={bits}")
    zlib.decompress(b64url_decode(wide_list["lst"]))

    empty_id = publish(base_url, token, [])
    _, empty_claims, _ = fetch_jwt(base_url, empty_id, verifier)
    empty_lst = empty_claims["status_list"]["lst"]
    try:
        zlib.decompress(b64url_decode(empty_lst))
    except zlib.error:
        decode_failed = True
    else:
        decode_failed = False
    if empty_lst != "" or not decode_failed:
        raise PocError("expected empty lst to fail independent ZLIB decoding")
    print(
        '[2/6] poc_2_invalid_signed_status_representation: bits=9; lst="" is not ZLIB'
    )


def poc_3_stale_cache_after_acknowledged_update(
    pod_a: str,
    pod_b: str,
    token: str,
    verifier: StatusTokenVerifier,
) -> None:
    """PoC 3: one process re-signs stale status after another acknowledges PATCH.

    Contract: https://github.com/adorsys/status-list-server/blob/adbe8fdacae5edb1ce655a14a5f5f2120ea229e3/docs/openapi.yaml#L264-L304
    Specification: https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-21.html#section-3
    """
    list_id = publish(pod_b, token, [{"index": 0, "status": VALID}])
    _, before_claims, before_headers = fetch_jwt(pod_a, list_id, verifier)
    before_status = decode_status(before_claims, 0)
    time.sleep(1.1)
    status, _, body = http_request(
        "PATCH",
        f"{pod_b}/api/v1/status-lists/{list_id}/statuses",
        {"statuses": [{"index": 0, "status": INVALID}]},
        {"Authorization": f"Bearer {token}"},
    )
    require_status(status, 200, "status update through pod B", body)
    _, writer_claims, writer_headers = fetch_jwt(pod_b, list_id, verifier)
    _, stale_claims, stale_headers = fetch_jwt(pod_a, list_id, verifier)
    if not (
        before_status == VALID
        and decode_status(writer_claims, 0) == INVALID
        and decode_status(stale_claims, 0) == VALID
        and writer_headers.get("etag") != stale_headers.get("etag")
        and stale_headers.get("etag") == before_headers.get("etag")
        and int(stale_claims["iat"]) > int(before_claims["iat"])
    ):
        raise PocError("expected cross-process stale-cache signature was not observed")
    print(
        "[3/6] poc_3_stale_cache_after_acknowledged_update: "
        "pod B=INVALID; pod A freshly signed cached VALID"
    )


def poc_4_expired_token_revalidation(
    base_url: str,
    token: str,
    verifier: StatusTokenVerifier,
) -> None:
    """PoC 4: an expired retained JWT receives a bodyless HTTP 304.

    Specification: https://www.rfc-editor.org/rfc/rfc9110.html#section-8.8.1
    Specification: https://www.rfc-editor.org/rfc/rfc9111.html#section-4.3.4
    Specification: https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-21.html#section-8.3
    """
    list_id = publish(base_url, token, [{"index": 0, "status": VALID}])
    _, claims, headers = fetch_jwt(base_url, list_id, verifier)
    expiration = int(claims["exp"])
    delay = expiration - time.time() + 0.25
    if delay > 15:
        raise PocError("token expiration is too long for the bounded PoC configuration")
    time.sleep(max(0.0, delay))
    status, _, body = http_request(
        "GET",
        f"{base_url}/api/v1/status-lists/{list_id}",
        headers={
            "Accept": "application/statuslist+jwt",
            "If-None-Match": headers["etag"],
        },
    )
    if status != 304 or body or int(time.time()) < expiration:
        raise PocError("expected expired representation to receive HTTP 304 without a body")
    _, replacement_claims, _ = fetch_jwt(base_url, list_id, verifier)
    if int(replacement_claims["exp"]) <= expiration:
        raise PocError("unconditional GET did not return a newly valid token")
    print(
        "[4/6] poc_4_expired_token_revalidation: expired JWT -> HTTP 304/no body; "
        "unconditional GET -> fresh HTTP 200"
    )


def poc_5_empty_patch_writes_full_snapshot(
    base_url: str,
    token: str,
    compose_file: Path,
    project_name: str,
) -> str:
    """PoC 5: an empty PATCH advances version and persists another full snapshot.

    Contract: https://github.com/adorsys/status-list-server/blob/adbe8fdacae5edb1ce655a14a5f5f2120ea229e3/docs/openapi.yaml#L264-L296
    Contract: https://github.com/adorsys/status-list-server/blob/adbe8fdacae5edb1ce655a14a5f5f2120ea229e3/docs/openapi.yaml#L481-L496
    """
    list_id = publish(base_url, token, [{"index": 0, "status": INVALID}])
    before_timestamp, before_rows, before_payloads = database_state(
        compose_file, project_name, list_id
    )
    status, _, body = http_request(
        "PATCH",
        f"{base_url}/api/v1/status-lists/{list_id}/statuses",
        {"statuses": []},
        {"Authorization": f"Bearer {token}"},
    )
    require_status(status, 200, "empty status update", body)
    after_timestamp, after_rows, after_payloads = database_state(
        compose_file, project_name, list_id
    )
    if not (
        after_timestamp > before_timestamp
        and after_rows == before_rows + 1
        and before_payloads == 1
        and after_payloads == 1
    ):
        raise PocError(
            "empty PATCH did not produce the expected newer version and duplicate full snapshot"
        )
    print(
        "[5/6] poc_5_empty_patch_writes_full_snapshot: "
        f"updated_at advanced; history rows {before_rows}->{after_rows}; payload variants=1"
    )
    return list_id


def poc_6_health_ignores_signing_failure(broken_url: str, list_id: str) -> None:
    """PoC 6: health remains positive while a body-producing signed GET fails.

    Platform policy: https://kubernetes.io/docs/concepts/workloads/pods/probes/#readiness-probe
    Contract: https://github.com/adorsys/status-list-server/blob/adbe8fdacae5edb1ce655a14a5f5f2120ea229e3/docs/openapi.yaml#L112-L125
    """
    health, _, health_body = http_request("GET", f"{broken_url}/health")
    require_status(health, 200, "broken-signer health check", health_body)
    get_status, _, _ = http_request(
        "GET",
        f"{broken_url}/api/v1/status-lists/{list_id}",
        headers={"Accept": "application/statuslist+jwt"},
    )
    if get_status < 500:
        raise PocError(f"expected signer-dependent GET to fail, observed HTTP {get_status}")
    print(
        "[6/6] poc_6_health_ignores_signing_failure: "
        f"/health=HTTP 200; signed GET=HTTP {get_status}"
    )


def main() -> None:
    script_dir = Path(__file__).resolve().parent
    repository_root = script_dir.parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pod-a-url", default="http://127.0.0.1:18004")
    parser.add_argument("--pod-b-url", default="http://127.0.0.1:18005")
    parser.add_argument("--broken-signer-url", default="http://127.0.0.1:18006")
    parser.add_argument("--compose-file", type=Path, default=script_dir / "docker-compose.yml")
    parser.add_argument("--project-name", default="application-functional-bugs")
    parser.add_argument(
        "--signing-key", type=Path, default=repository_root / "test_data/ec-private.pem"
    )
    parser.add_argument(
        "--confirm-disposable-target",
        action="store_true",
        help="required acknowledgement that all targets are local and disposable",
    )
    args = parser.parse_args()
    if not args.confirm_disposable_target:
        parser.error("--confirm-disposable-target is required before any write")

    pod_a = require_loopback_url(args.pod_a_url)
    pod_b = require_loopback_url(args.pod_b_url)
    broken_url = require_loopback_url(args.broken_signer_url)
    if len({pod_a, pod_b, broken_url}) != 3:
        parser.error("pod A, pod B, and broken-signer URLs must be distinct")
    compose_file = args.compose_file.resolve()
    signing_key = args.signing_key.resolve()
    if not compose_file.is_file() or not signing_key.is_file():
        parser.error("compose file and checked-in test signing key must exist")

    for label, base_url in (("pod A", pod_a), ("pod B", pod_b), ("broken signer", broken_url)):
        wait_for_health(label, base_url)

    with tempfile.TemporaryDirectory(prefix="status-list-functional-poc-") as temp_dir:
        directory = Path(temp_dir)
        issuer = EphemeralIssuer(directory)
        verifier = StatusTokenVerifier(signing_key, directory)
        status, _, body = http_request(
            "POST",
            f"{pod_b}/api/v1/credentials",
            {"issuer": issuer.issuer, "public_key": issuer.jwk},
        )
        require_status(status, 202, "synthetic credential registration", body)
        token = issuer.management_token()

        poc_1_openapi_status_contract_mismatch(pod_b, token)
        poc_2_invalid_signed_status_representation(pod_b, token, verifier)
        poc_3_stale_cache_after_acknowledged_update(pod_a, pod_b, token, verifier)
        poc_4_expired_token_revalidation(pod_b, token, verifier)
        readiness_list_id = poc_5_empty_patch_writes_full_snapshot(
            pod_b, token, compose_file, args.project_name
        )
        poc_6_health_ignores_signing_failure(broken_url, readiness_list_id)

    print(f"\nRESULT: six functional failures reproduced at baseline {BASELINE}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, PocError, subprocess.SubprocessError) as error:
        raise SystemExit(f"PoC failed: {error}") from error
