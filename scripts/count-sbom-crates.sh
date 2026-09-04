#!/bin/sh
# Count distinct pkg:cargo/ purls in a BuildKit-published SBOM.
#
# Shared by the collect and assert steps in deploy.yml so the number printed into
# the job summary and the number the assertion tests cannot drift apart.
#
# `unique` matters: each purl appears in both externalRefs and relationships, so a
# bare count reports a multiple of the real number. A cargo purl rather than a
# package count, because SPDX includes a synthetic package describing the image
# itself, which would satisfy a bare not-empty check on nothing.
set -eu

sbom=${1:?usage: count-sbom-crates.sh <sbom.json>}

jq '[.. | strings | select(startswith("pkg:cargo/"))] | unique | length' "$sbom"
