#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: $0 <issuers.yaml> <issuer> <stored-aggregation-id>" >&2
  exit 2
fi

registry=$1
issuer=$2
stored_id=$3
exported_id=$(ISSUER="$issuer" yq -er '.issuers[] | select(.id == strenv(ISSUER)) | .aggregation_id' "$registry")
[[ -n "$stored_id" && "$stored_id" == "$exported_id" ]] || {
  echo "aggregation ID for $issuer does not match its exported registry entry" >&2
  exit 1
}
