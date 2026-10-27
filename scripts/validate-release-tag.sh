#!/usr/bin/env bash
# Fail unless the pushed ref is a semver tag: v*.*.* also matches v2024.01.release,
# which would make the deploy fall through to latest.
# Usage: validate-release-tag.sh <ref_name> <is_tag>

set -euo pipefail

REF_NAME="${1-}"
IS_TAG="${2-}"

if [ "$IS_TAG" != "true" ]; then
  echo "Not a tag push -- nothing to validate."
  exit 0
fi

# No build metadata: + isn't allowed in Docker tags.
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
