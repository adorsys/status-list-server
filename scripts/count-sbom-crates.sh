#!/bin/sh
# Count distinct pkg:cargo purls in a BuildKit SBOM.
# unique: each purl appears twice in SPDX, and the image's own package would satisfy a bare count.
set -eu

sbom=${1:?usage: count-sbom-crates.sh <sbom.json>}

jq '[.. | strings | select(startswith("pkg:cargo/"))] | unique | length' "$sbom"
