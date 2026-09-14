from enum import IntEnum
from pathlib import Path
from dotenv import dotenv_values
import unittest
import cbor2
import zlib
import base64


# Handy handle for test-like assertions
tc = unittest.TestCase()

# RFC 9052 §4.2
COSE_SIGN1_TAG = 18


class Status(IntEnum):
    """Token status values as sent to the server."""
    VALID = 0
    INVALID = 1


def get_base_url():
    """
    Discovers the base URL for the server based on a .env file at the project root.

    If APP_SERVER__PORT is set in the .env file, it returns "http://localhost:APP_SERVER__PORT".
    Otherwise, it defaults to "http://localhost:8000".

    Returns:
        str: The determined base URL (e.g., "http://localhost:8000").
    """
    project_root = Path(__file__).resolve().parents[3]
    dotenv_vars = dotenv_values(project_root / ".env")
    port = dotenv_vars.get("APP_SERVER__PORT") or 8000

    return f"http://localhost:{port}"


def is_valid_cwt(cwt_data: bytes) -> bool:
    """
    Verifies if provided bytes represent a valid CWT wrapped in a COSE_Sign1 structure.
    """
    try:
        decoded = cbor2.loads(cwt_data)

        if isinstance(decoded, cbor2.CBORTag) and decoded.tag == COSE_SIGN1_TAG:
            decoded = decoded.value

        # Check if COSE_Sign1 structure
        # cbor2 decodes arrays nested in a tag as tuples.
        if isinstance(decoded, (list, tuple)) and len(decoded) == 4:
            protected, unprotected, payload, signature = decoded

            if not isinstance(payload, bytes):
                print("COSE_Sign1 payload is not bytes.")
                return False

            # Now decode the payload (the actual CWT claims)
            cwt_claims = cbor2.loads(payload)

            if isinstance(cwt_claims, dict):
                standard_claims = {1, 2, 3, 4, 5, 6}  # 'iss', 'sub', etc.
                if any(claim in cwt_claims for claim in standard_claims):
                    return True
                else:
                    print("Decoded CWT payload but missing standard claims.")
                    return False
            else:
                print("Decoded payload but not a dict.")
                return False

        else:
            print("Decoded data is not a COSE_Sign1 structure (array of 4 elements).")
            return False

    except (cbor2.CBORDecodeError, ValueError) as e:
        print(f"Failed to decode CBOR: {e}")
        return False


def decode_and_decompress(encoded: str) -> bytes:
    padded_encoded = encoded + '=' * \
        (-len(encoded) % 4)  # Add padding if necessary
    compressed = base64.urlsafe_b64decode(padded_encoded)
    return zlib.decompress(compressed)
