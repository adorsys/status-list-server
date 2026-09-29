#!/usr/bin/env bash
set -euo pipefail

MICROCKS_IMAGE_DEFAULT="quay.io/microcks/microcks-cli@sha256:7c0ea4c73f68e17614512499d5d707b52fa6d2539375778efa760c10cf25aa2e"
MICROCKS_UBER_IMAGE_DEFAULT="quay.io/microcks/microcks-uber@sha256:c0daa6b10aefccb68341828dc98d9fd540f8fd5aa4485ed41c2f428582593d91"
NEWMAN_DOCKER_IMAGE_DEFAULT="postman/newman@sha256:02dc4a285dc05aa3a3f4035e5425a83f3b4cdb21afb71c79df589cbac0a0e04f"

images=(
  "${MICROCKS_IMAGE:-$MICROCKS_IMAGE_DEFAULT}"
  "${MICROCKS_UBER_IMAGE:-$MICROCKS_UBER_IMAGE_DEFAULT}"
  "${NEWMAN_DOCKER_IMAGE:-$NEWMAN_DOCKER_IMAGE_DEFAULT}"
)

for image in "${images[@]}"; do
  case "$image" in
    *@sha256:*) ;;
    *)
      echo "Image is not pinned by digest: $image" >&2
      exit 1
      ;;
  esac

  echo "Checking image: $image"
  docker pull --quiet "$image" >/dev/null
done
