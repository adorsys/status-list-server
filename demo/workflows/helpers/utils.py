from pathlib import Path
from dotenv import dotenv_values
import unittest
import cbor2
import zlib
import base64


# Handy handle for test-like assertions
tc = unittest.TestCase()


def get_base_url():
    """
    Discovers the base URL for the server based on a .env file at the project root.

    If a PORT variable is found in the .env file, it returns "http://localhost:PORT".
    Otherwise, it defaults to "http://localhost:8000".

    Returns:
        str: The determined base URL (e.g., "http://localhost:8000").
    """
    # Navigate to the project root
    workflows_dir = Path(__file__).parent.parent
    project_root = workflows_dir.parent.parent

    # Path to the .env file at the root
    dotenv_path = project_root / '.env'

    # Load the .env file - will load if it exists at the specified path
    dotenv_vars = dotenv_values(dotenv_path)

    # Get the PORT variable from the loaded env vars
    port = dotenv_vars.get("PORT", 8000)

    # Construct the base URL
    base_url = f"http://localhost:{port}"

    return base_url


def is_valid_cwt(cwt_data: bytes) -> bool:
    """
    Verifies if provided bytes represent a valid CWT (possibly COSE_Sign1-wrapped).
    """
    try:
        decoded = cbor2.loads(cwt_data)

        # Check if COSE_Sign1 structure
        if isinstance(decoded, list) and len(decoded) == 4:
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
