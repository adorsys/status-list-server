"""Create or renew a sandbox issuer on the private admin listener."""

import argparse
import getpass
import json
import time
from pathlib import Path
from urllib.parse import quote

import requests


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://localhost:8002")
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create")
    create.add_argument("--display-name", required=True)
    create.add_argument("--owner", required=True)
    create.add_argument("--public-key", required=True, type=Path)
    create.add_argument("--alg", required=True)
    renew = commands.add_parser("renew")
    renew.add_argument("--issuer", required=True)
    renew.add_argument("--days", type=int, default=30)
    args = parser.parse_args()

    headers = {"Authorization": f"Bearer {getpass.getpass('Admin token: ')}"}
    endpoint = f"{args.url.rstrip('/')}/admin/v1/issuers"
    if args.command == "create":
        body = {
            "display_name": args.display_name,
            "owner": args.owner,
            "public_key": json.loads(args.public_key.read_text()),
            "alg": args.alg,
        }
        response = requests.post(
            endpoint, headers=headers, json=body, timeout=30, allow_redirects=False
        )
    else:
        endpoint += f"/{quote(args.issuer, safe='')}"
        current = requests.get(
            endpoint, headers=headers, timeout=30, allow_redirects=False
        )
        if current.status_code != 200:
            raise SystemExit(f"Admin read failed with HTTP {current.status_code}")
        if current.json().get("tier") != "sandbox":
            raise SystemExit("Only sandbox issuers support expiry renewal")
        headers["If-Match"] = current.headers["ETag"]
        response = requests.patch(
            endpoint,
            headers=headers,
            json={"expires_at": int(time.time()) + args.days * 24 * 60 * 60},
            timeout=30,
            allow_redirects=False,
        )
    if response.status_code not in (200, 201):
        raise SystemExit(f"Admin write failed with HTTP {response.status_code}")
    print(json.dumps(response.json(), indent=2))


if __name__ == "__main__":
    main()
