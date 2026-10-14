#!/usr/bin/env python3
"""Generate a self-signed certificate and signing key for a local Status List Server.

The server signs status list tokens with an ECDSA P-256 key and refuses to start
without a certificate whose public key matches it. This writes such a pair as
`tls.crt` (PEM certificate) and `tls.key` (PKCS#8 PEM private key), for local
development only.

Existing files are left untouched unless --force is given.

Usage: generate-dev-cert.py [--out-dir PATH] [--force]
"""

from __future__ import annotations

import argparse
import datetime
import os
import pathlib
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
HOSTNAME = "localhost"
VALIDITY = datetime.timedelta(days=365)


def build_certificate(key: ec.EllipticCurvePrivateKey) -> x509.Certificate:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, HOSTNAME)])
    now = datetime.datetime.now(datetime.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + VALIDITY)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(HOSTNAME)]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        # An ECDSA key only signs, so digitalSignature is the one usage that applies.
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )


def write_temp_file(path: pathlib.Path, data: bytes, mode: int) -> pathlib.Path:
    """Write data to a fresh temporary file next to path and return the temporary path.

    The file is created with the given mode, which os.replace keeps when it moves the
    file into place. The mode takes effect on POSIX only; Windows applies inherited ACLs.
    """
    temp_path = path.with_name(f".{path.name}.tmp")
    temp_path.unlink(missing_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    with os.fdopen(os.open(temp_path, flags, mode), "wb") as file:
        file.write(data)
    return temp_path


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate a self-signed certificate and signing key for local development."
    )
    parser.add_argument(
        "--out-dir",
        type=pathlib.Path,
        default=REPO_ROOT,
        help="directory to write tls.crt and tls.key to (default: repository root)",
    )
    parser.add_argument("--force", action="store_true", help="overwrite existing files")
    args = parser.parse_args()

    if not args.out_dir.is_dir():
        print(f"error: {args.out_dir} is not a directory", file=sys.stderr)
        return 1

    cert_path = args.out_dir / "tls.crt"
    key_path = args.out_dir / "tls.key"

    # Checked for both files up front so a refusal never leaves a mismatched pair behind.
    existing = [path for path in (cert_path, key_path) if path.exists()]
    if existing and not args.force:
        for path in existing:
            print(f"error: {path} already exists; pass --force to replace it", file=sys.stderr)
        return 1

    key = ec.generate_private_key(ec.SECP256R1())
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    cert_pem = build_certificate(key).public_bytes(serialization.Encoding.PEM)

    # Both files are fully written before either replaces an existing one, so a failed
    # write leaves the previous pair intact instead of a new key next to an old certificate.
    temp_paths = []
    try:
        temp_paths.append(write_temp_file(key_path, key_pem, 0o600))
        temp_paths.append(write_temp_file(cert_path, cert_pem, 0o644))
        os.replace(temp_paths[0], key_path)
        os.replace(temp_paths[1], cert_path)
    finally:
        for temp_path in temp_paths:
            temp_path.unlink(missing_ok=True)

    print(f"wrote {cert_path}")
    print(f"wrote {key_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
