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
            "alg": "RS256",
            "public_key": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs4Df4EUySK6d7pRQkLhM6lbgtSuKwDOnJ3IpUyiP6yY8Bl4+ksmSC3Q3xe9KgAltkQd+hVo/3bSw1Mn5Ozzcs+xXTkt7IIDpFE8wWe4sPdm1+OZ0tZb3FWJV2fM4ZsFeo6+ucaiZjmUIeq+xccMaNcPkP6xhBtlMXuvtf2PkKqov9Im8MgmrTwSMZa1AWHo0bgS5AdB9n3KKjp75CCTtLdT4/fRpehgfu9F+QHPl6YYHSKNEYzzSt+Ix0A76IYceuryQFps3iIVDRlFAqfFTjHlP3Cg7byhjee4YCqL9YwTSLyRVxYKfUU9byiDGqf9jeiXZRssVNLK99c8MxzEvfwIDAQAB",
            "private_key": "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCzgN/gRTJIrp3ulFCQuEzqVuC1K4rAM6cncilTKI/rJjwGXj6SyZILdDfF70qACW2RB36FWj/dtLDUyfk7PNyz7FdOS3sggOkUTzBZ7iw92bX45nS1lvcVYlXZ8zhmwV6jr65xqJmOZQh6r7Fxwxo1w+Q/rGEG2Uxe6+1/Y+Qqqi/0ibwyCatPBIxlrUBYejRuBLkB0H2fcoqOnvkIJO0t1Pj99Gl6GB+70X5Ac+XphgdIo0RjPNK34jHQDvohhx66vJAWmzeIhUNGUUCp8VOMeU/cKDtvKGN57hgKov1jBNIvJFXFgp9RT1vKIMap/2N6JdlGyxU0sr31zwzHMS9/AgMBAAECggEBALDjQLq6tbCWEp/2m+XhGDqdXlZqEBMTU5c1kq+V+yzYwrHr0XHJHRgYcJWnFx1RLR2L6wvyQZly5Abs+aN8eGj9b5OCIlWHcyhGWPlmEUbp8b7TKxN/LwFto/hhC6WGzII1L4xlftyph0+PLydSAdQVtCli70JWhEHN8H5mq4O2BxNRY5pnjiKbCu/eX3DnlM+0ZrYfOFHCV6fJPi1mADX4DQcaYjWYJ+NKGX3/dAf9RTTV2d9HDR6DMVedKCPOqxbhPk4H6b8WZ2YG1DYUODUrtS04aOCI2+zl38ihvMfYQJdim/xb9b8ycrSNgLImBWI1WJ4wc6m3ugkIQFc8M8ECgYEA4KV9V6PtNTqp5OO3YpCN7VOfQ3VIeQh0iF6obNOD1myUsC2PjSPY5RifZwTdTDeEPZ91fAk+W3iwwy7BYZhELGhs4Xq2OFXendr5Q9aQteDZqhTxLABYT/juGlipS9o8C9Y2CQ0fH33BUVXQ7oherTO9rTe6P1dsoTxIzWGLCjECgYEAzI5yLvaas/zmEYAJYzfok5go6YAbytbNIqTI/nvaVHU4sYd3ryv1RYxpMcx9pKluh7NEUaBuBpXJ0qtMWB49UG98ENKet4SHn1IwA5/N/v7sJoYQsFeBfCtIxDdE5mIlwmysrMtyk+k+rMpD8oxr+DHUw+lrecn60mXH4qByuK8CgYBieunZ07kXTqJP/yvTf79YPQJiljWxKW28opJ/MrJm+66rFS4LF53rwMGQbed9lBDa2t6sA3lcrCoBRqvr1s58EUM6DYt4Ytx2oxoHDTbfJLUHBKs9OOF+HYhz8E43PHJ6VevWR/RO39gxicdP6mRm1XnfR8DUJ8UtYbognxRO4QKBgFjkjjpacGBHRrPUMEAty6RYO289fNZpAjxL4Ay3RenuBvUfKaO2NqBCpHQ/qVolRyMxhD70uNujvFEQn9yrR3ns+L1WyiJ2NXnG/ZaVm690mKslF5uKa3rKVJTwb8CuZjpXf7KXtvMQKWxteZmt7D2vaga5KTuDyrwj/vk9QJ2BAoGBAKInb9rh5kfZ199PnSALPhfVSfZVNH6zpNMp4cXmuL9uqguA/csR3jgU/TOxE9wwmovCkpKwViOlPlKpESWGMOg1Es9KDLN86nLhsJ1Hpk009sDZ4AoJPhipH9R/7964Ow5L7DpS5MFkkgrK+68kmBBosxTPgs2NLzMQlF3xGrOV",
        }
    }
    return issuer_data
