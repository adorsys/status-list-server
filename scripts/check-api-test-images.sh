#!/usr/bin/env bash
set -euo pipefail

NEWMAN_DOCKER_IMAGE_DEFAULT="postman/newman@sha256:02dc4a285dc05aa3a3f4035e5425a83f3b4cdb21afb71c79df589cbac0a0e04f"

images=(
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
