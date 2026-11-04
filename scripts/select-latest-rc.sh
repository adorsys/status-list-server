#!/usr/bin/env bash
# Print the highest-numbered v<version>-rc.<N> tag among the tag names read on stdin.
# Errors go to stderr: callers capture stdout as the tag.
# A final release ships this RC's image, so lookalikes such as v1.2.30-rc.1 must never match.
# Usage: select-latest-rc.sh <version> < tag-names
set -euo pipefail
# [[ > ]] collates by locale; C keeps the digit comparison byte-wise.
export LC_ALL=C

version=${1-}

if [[ ! "$version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
    echo "::error::'${version}' is not a final release version shaped like 1.2.3." >&2
    exit 1
fi

prefix="v${version}-rc."
best_n=""
best_tag=""

while IFS= read -r tag || [ -n "$tag" ]; do
    [[ "$tag" == "$prefix"* ]] || continue
    n=${tag#"$prefix"}
    # A string prefix, not a regex, so the dots in the version need no escaping.
    [[ "$n" =~ ^(0|[1-9][0-9]*)$ ]] || continue
    # Leading zeros are rejected above, so a longer digit string is the larger number and
    # equal lengths compare lexically. Unlike -gt, this has no integer range to overflow.
    if [ -z "$best_n" ] || [ "${#n}" -gt "${#best_n}" ] ||
        { [ "${#n}" -eq "${#best_n}" ] && [[ "$n" > "$best_n" ]]; }; then
        best_n=$n
        best_tag=$tag
    fi
done

if [ -z "$best_tag" ]; then
    echo "::error::no ${prefix}<N> tag exists, so there is no validated image to release as v${version}." >&2
    echo "A final release never rebuilds the image. Cut and validate v${version}-rc.1 first." >&2
    exit 1
fi

printf '%s\n' "$best_tag"
