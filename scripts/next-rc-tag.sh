#!/usr/bin/env bash
# Print the next RC tag for a Cargo package version from tag refs read on stdin.

set -euo pipefail

VERSION="${1-}"
semver='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'

if [[ ! "$VERSION" =~ $semver ]]; then
  echo "::error::Cargo package version '$VERSION' is not a release semver version." >&2
  exit 1
fi

next=1
highest_final=""
while IFS=$'\t' read -r _ ref; do
  tag="${ref#refs/tags/}"
  tag="${tag%^\{\}}"

  if [[ "${tag#v}" =~ $semver ]] && [[ "$tag" == v* ]]; then
    final_version="${tag#v}"
    if [ -z "$highest_final" ] || [ "$(printf '%s\n%s\n' "$highest_final" "$final_version" | sort -V | tail -n1)" = "$final_version" ]; then
      highest_final="$final_version"
    fi
  fi

  if [[ "$tag" =~ ^v([0-9]+\.[0-9]+\.[0-9]+)-rc\.([1-9][0-9]*)$ ]] && [ "${BASH_REMATCH[1]}" = "$VERSION" ]; then
    candidate=$((10#${BASH_REMATCH[2]} + 1))
    if [ "$candidate" -gt "$next" ]; then
      next="$candidate"
    fi
  fi
done

if [ -n "$highest_final" ] && [ "$(printf '%s\n%s\n' "$VERSION" "$highest_final" | sort -V | tail -n1)" = "$highest_final" ]; then
  echo "::error::Final release v$highest_final already exists; stage version $VERSION must be newer before creating an RC." >&2
  exit 1
fi

printf 'v%s-rc.%s\n' "$VERSION" "$next"
