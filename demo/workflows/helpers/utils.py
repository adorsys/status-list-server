from enum import IntEnum
from pathlib import Path
from dotenv import dotenv_values
import os
import unittest
import cbor2
import zlib
import base64


# Handy handle for test-like assertions
tc = unittest.TestCase()

# RFC 9052 §4.2
COSE_SIGN1_TAG = 18

# CWT claim key for status_list (draft-ietf-oauth-status-list), as the server sends it
CWT_STATUS_LIST_CLAIM = 65533


class Status(IntEnum):
    """Token status values as sent to the server."""
    VALID = 0
    INVALID = 1


def get_base_url():
    """
    Discovers the base URL for the server from the APP_SERVER__PORT variable.

    The variable is read from the environment first, then from a .env file at
    the project root, mirroring how the server resolves it. Without either, it
    defaults to port 8000.

    Returns:
        str: The determined base URL (e.g., "http://localhost:8000").
    """
    project_root = Path(__file__).resolve().parents[3]
    port = (
        os.environ.get("APP_SERVER__PORT")
        or dotenv_values(project_root / ".env").get("APP_SERVER__PORT")
        or 8000
    )

    return f"http://localhost:{port}"


def is_valid_cwt(cwt_data: bytes) -> bool:
    """
    Verifies if provided bytes represent a status list CWT: a tagged COSE_Sign1
    structure (RFC 9052 §4.2) whose payload carries a status_list claim.
    """
    try:
        decoded = cbor2.loads(cwt_data)

        if not (isinstance(decoded, cbor2.CBORTag) and decoded.tag == COSE_SIGN1_TAG):
            print(f"Decoded data is not tagged as COSE_Sign1 (CBOR tag {COSE_SIGN1_TAG}).")
            return False

        # cbor2 decodes arrays nested in a tag as tuples.
        sign1 = decoded.value
        if not (isinstance(sign1, (list, tuple)) and len(sign1) == 4):
            print("Decoded data is not a COSE_Sign1 structure (array of 4 elements).")
            return False

        protected, unprotected, payload, signature = sign1
        if not isinstance(payload, bytes):
            print("COSE_Sign1 payload is not bytes.")
            return False

        # Now decode the payload (the actual CWT claims)
        cwt_claims = cbor2.loads(payload)
        if not isinstance(cwt_claims, dict):
            print("Decoded payload but not a dict.")
            return False

        status_list = cwt_claims.get(CWT_STATUS_LIST_CLAIM)
        if not (
            isinstance(status_list, dict)
            and isinstance(status_list.get("bits"), int)
            and isinstance(status_list.get("lst"), bytes)
        ):
            print("Decoded CWT payload but missing a valid status_list claim.")
            return False

        return True

    except (cbor2.CBORDecodeError, ValueError) as e:
        print(f"Failed to decode CBOR: {e}")
        return False


def get_status(statuses: bytes, index: int, bits: int) -> int:
    """
    Reads the status at a given index from a decompressed status list.

    Statuses are packed `bits` wide, least significant bit first
    (draft-ietf-oauth-status-list §4.1).
    """
    position = index * bits
    return (statuses[position // 8] >> (position % 8)) & ((1 << bits) - 1)


def decode_and_decompress(encoded: str) -> bytes:
    padded_encoded = encoded + '=' * \
        (-len(encoded) % 4)  # Add padding if necessary
    compressed = base64.urlsafe_b64decode(padded_encoded)
    return zlib.decompress(compressed)
