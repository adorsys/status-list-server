from enum import IntEnum
from pathlib import Path
from dotenv import dotenv_values
import os
import unittest
import cbor2
import zlib
import base64


tc = unittest.TestCase()

# RFC 9052 §4.2
COSE_SIGN1_TAG = 18

# CWT claim key for status_list (draft-ietf-oauth-status-list), as the server sends it
CWT_STATUS_LIST_CLAIM = 65533


class Status(IntEnum):
    VALID = 0
    INVALID = 1
    SUSPENDED = 2


def get_base_url():
    """Port from APP_SERVER__PORT (env, then .env), default 8000, like the server."""
    project_root = Path(__file__).resolve().parents[3]
    port = (
        os.environ.get("APP_SERVER__PORT")
        or dotenv_values(project_root / ".env").get("APP_SERVER__PORT")
        or 8000
    )

    return f"http://localhost:{port}"


def get_management_url():
    """Port from APP_SERVER__MANAGEMENT__PORT (env, then .env), default 8001.
    Always localhost: the server's bind address isn't something to connect to.
    """
    project_root = Path(__file__).resolve().parents[3]
    port = (
        os.environ.get("APP_SERVER__MANAGEMENT__PORT")
        or dotenv_values(project_root / ".env").get("APP_SERVER__MANAGEMENT__PORT")
        or 8001
    )

    return f"http://localhost:{port}"


def decode_cwt_status_list(cwt_data: bytes) -> dict:
    """The status_list claim of a COSE_Sign1 CWT, as {bits, lst}.
    lst is raw zlib bytes here, not base64url: use decompress_bytes.
    """
    decoded = cbor2.loads(cwt_data)

    if not (isinstance(decoded, cbor2.CBORTag) and decoded.tag == COSE_SIGN1_TAG):
        raise ValueError(f"not a COSE_Sign1 (CBOR tag {COSE_SIGN1_TAG})")

    # cbor2 decodes arrays nested in a tag as tuples.
    sign1 = decoded.value
    if not (isinstance(sign1, (list, tuple)) and len(sign1) == 4):
        raise ValueError("not a COSE_Sign1 structure (array of 4 elements)")

    _, _, payload, _ = sign1
    if not isinstance(payload, bytes):
        raise ValueError("COSE_Sign1 payload is not bytes")

    cwt_claims = cbor2.loads(payload)
    if not isinstance(cwt_claims, dict):
        raise ValueError("decoded payload is not a dict")

    status_list = cwt_claims.get(CWT_STATUS_LIST_CLAIM)
    if not (
        isinstance(status_list, dict)
        and isinstance(status_list.get("bits"), int)
        and isinstance(status_list.get("lst"), bytes)
    ):
        raise ValueError("missing a valid status_list claim")

    return status_list


def get_status(statuses: bytes, index: int, bits: int) -> int:
    """Statuses are packed bits wide, least significant bit first (§4.1)."""
    max_index = len(statuses) * 8 // bits - 1
    if not 0 <= index <= max_index:
        raise IndexError(f"index {index} out of range (0..{max_index})")
    position = index * bits
    return (statuses[position // 8] >> (position % 8)) & ((1 << bits) - 1)


def decompress_bytes(compressed: bytes) -> bytes:
    return zlib.decompress(compressed)


def decode_and_decompress(encoded: str) -> bytes:
    padded_encoded = encoded + '=' * \
        (-len(encoded) % 4)
    compressed = base64.urlsafe_b64decode(padded_encoded)
    return zlib.decompress(compressed)
