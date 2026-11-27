#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: $0 <latest-final|datev> <latest-final-tag> <datev-baseline-tag>" >&2
  exit 2
fi

baseline=$1
latest=$2
datev=$3
stable_tag='^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'

[[ "$latest" =~ $stable_tag ]] || {
  echo "::error::Latest final baseline is not a stable release tag." >&2
  exit 1
}
case "$baseline" in
  latest-final) tag=$latest; skip=false ;;
  datev)
    [[ "$datev" =~ $stable_tag ]] || {
      echo "::error::Set DATEV_BASELINE_TAG to the confirmed installed Datev final release tag." >&2
      exit 1
    }
    [[ $(printf '%s\n%s\n' "$latest" "$datev" | LC_ALL=C sort -V | tail -n 1) == "$latest" ]] || {
      echo "::error::DATEV_BASELINE_TAG is newer than the latest final release." >&2
      exit 1
    }
    tag=$datev
    [[ "$datev" == "$latest" ]] && skip=true || skip=false
    ;;
  *) echo "::error::Unknown direct-upgrade baseline: $baseline" >&2; exit 2 ;;
esac

printf 'tag=%s\nskip=%s\n' "$tag" "$skip"
