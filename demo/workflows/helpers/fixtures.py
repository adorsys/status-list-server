import random
import string

# ---------------------------------------------------------------------
# Example token issuer configurations
# These are placeholder structures for demonstration.
# In a real application, keypair information would be managed securely.
# ---------------------------------------------------------------------


def generate_random_string(length):
    """Generates a random string of specified length."""
    characters = string.ascii_lowercase + string.digits
    return ''.join(random.choice(characters) for i in range(length))


def get_gondwana_digital_pole_issuer():
    """
    Returns the Gondwana Digital Pole issuer dictionary with a random suffix
    appended to the label.
    """
    random_suffix = generate_random_string(5)
    issuer_data = {
        "label": f"gondwana-digital-pole-{random_suffix}",
        "keypair": {
            "alg": "ES256",
            "public_key": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEswasdMSg9Y6ZhBSheyx8KVq4ZkKuA54Azf8lVCj4zJ0mVV+CqG9obN+JTDGAQWzja9DKT0oyhUMgNDtQB94xTw==",
            "private_key": "MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCBqY2vsWCFZmTVGtyhSrEvpm08k1CpLdq63WcAdpstuEQ==",
        }
    }
    return issuer_data


def get_scott_holdings_issuer():
    """
    Returns the Scott Holdings issuer dictionary with a random suffix
    appended to the label.
    """
    random_suffix = generate_random_string(5)
    issuer_data = {
        "label": f"scott-holdings-{random_suffix}",
        "keypair": {
            "alg": "ES256",
            "public_key": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8902sCvjjr5thgD7y15w5b0fBT6ce4gBbWURxXZvIB/BWgGORMx7FJdJTOiJKFw2UERNG9pHOHqCC9c37bBtag==",
            "private_key": "MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCC4Qhay6z0HFXcag2RDrpp2kLiNBU5cpY+OmrtA5SfLjg==",
        }
    }
    return issuer_data
