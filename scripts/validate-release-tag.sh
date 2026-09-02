#!/usr/bin/env bash
#
# Assert that a pushed ref is a semver release tag.
#
# deploy.yml's push filter is `v*.*.*`, which is a refspec glob rather than semver:
# `v2024.01.release` matches it. On such a tag docker/metadata-action drops every
# `type=semver` entry, `promote-tags` produces no tags, and the deploy would fall
# through to the mutable `latest` instead of failing. This rejects them at the top
# of the release, in seconds, before the ~40 minute two-arch build.
#
# Lives here rather than inline in deploy.yml so the contract has one definition and
# scripts/tests/test_validate_release_tag.py can exercise it.
#
# Usage: validate-release-tag.sh <ref_name> <is_tag>
#   ref_name  github.ref_name
#   is_tag    "true" when github.ref starts with refs/tags/v; anything else is a
#             non-tag run (workflow_dispatch), which has no tag to validate.

set -euo pipefail

REF_NAME="${1-}"
IS_TAG="${2-}"

if [ "$IS_TAG" != "true" ]; then
  echo "Not a tag push -- nothing to validate."
  exit 0
fi

# Build metadata (`+...`) is deliberately absent from the alternation: `+` is not a
# legal character in a Docker image tag, so a `v1.2.3+meta` release could never be
# published under its own version.
semver='^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$'

if [[ ! "$REF_NAME" =~ $semver ]]; then
  echo "::error::Tag '${REF_NAME}' matched the v*.*.* push filter but is not semver."
  echo "metadata-action would drop every type=semver entry, and the deploy job"
  echo "would fall through to the mutable 'latest' tag instead of failing."
  echo "Delete the tag and push one shaped like v1.2.3 or v1.2.3-rc.1."
  echo
  echo "Build metadata (a '+' suffix) is rejected too: '+' is not a legal"
  echo "character in a Docker image tag."
  exit 1
fi

echo "Tag '${REF_NAME}' is valid semver."
