"""Read issuer metadata on the private admin listener."""

import argparse
import getpass
import json
from urllib.parse import quote

import requests


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://localhost:8002")
    parser.add_argument("--issuer")
    args = parser.parse_args()
    headers = {"Authorization": f"Bearer {getpass.getpass('Admin token: ')}"}
    endpoint = f"{args.url.rstrip('/')}/admin/v1/issuers"
    if args.issuer is not None:
        endpoint += f"/{quote(args.issuer, safe='')}"
    params = {} if args.issuer is not None else {"limit": 50}
    while True:
        response = requests.get(endpoint, headers=headers, params=params, timeout=30, allow_redirects=False)
        if response.status_code != 200:
            raise SystemExit(f"Admin request failed with HTTP {response.status_code}")
        response.raise_for_status()
        body = response.json()
        if args.issuer is not None:
            print(f"ETag: {response.headers['ETag']}")
            print(json.dumps(body, indent=2))
            return
        print(json.dumps(body["issuers"], indent=2))
        cursor = body["next_cursor"]
        if cursor is None:
            return
        params["cursor"] = cursor


if __name__ == "__main__":
    main()
