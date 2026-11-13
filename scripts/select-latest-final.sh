#!/usr/bin/env bash
# Print the highest stable v<major>.<minor>.<patch> tag read on stdin.
set -euo pipefail

tags=()
while IFS= read -r tag || [[ -n "$tag" ]]; do
  if [[ "$tag" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
    tags+=("$tag")
  fi
done

if (( ${#tags[@]} )); then
  printf '%s\n' "${tags[@]}" | LC_ALL=C sort -V | tail -n 1
fi
