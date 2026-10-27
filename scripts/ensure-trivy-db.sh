#!/usr/bin/env bash
# Refresh the Trivy DB, or fall back to a cached one younger than the bound.
# Usage: ensure-trivy-db.sh <cache-dir> <staleness-bound-hours> (cache-dir must be absolute).
# Shared by deploy.yml and the nightly scan; keep it in step with their cache keys.

set -euo pipefail

CACHE_DIR="${1:-}"
STALE_HOURS="${2:-24}"

if [ -z "${CACHE_DIR}" ]; then
  echo "::error::ensure-trivy-db.sh: cache-dir argument required"
  exit 1
fi

case "${STALE_HOURS}" in
  '' | *[!0-9]*)
    echo "::error::ensure-trivy-db.sh: staleness bound must be a whole number of hours, got '${STALE_HOURS}'"
    exit 1
    ;;
esac

mkdir -p "${CACHE_DIR}"

# --skip-db-update needs both files, so both must exist for the cache to count.
DB_FILE="${CACHE_DIR}/db/trivy.db"
META_FILE="${CACHE_DIR}/db/metadata.json"

summary() {
  {
    echo "### Trivy vulnerability database"
    echo
    printf '%s\n' "$@"
  } >> "${GITHUB_STEP_SUMMARY:-/dev/null}"
}

# Trivy downloads to a temp dir first, so a failed fetch leaves the cache intact.
echo "Refreshing Trivy vulnerability database..."
if trivy image --download-db-only --cache-dir "${CACHE_DIR}" 2>&1; then
  summary "Database refreshed successfully."
  exit 0
fi

echo "::warning::Failed to refresh Trivy vulnerability database; checking for cached DB..."

if [ ! -f "${DB_FILE}" ] || [ ! -f "${META_FILE}" ]; then
  echo "::error::No Trivy vulnerability database available and download failed."
  summary "**Error:** No vulnerability database available and download failed." \
    "The scan cannot proceed without a database."
  exit 1
fi

# GNU stat takes -c %Y, BSD takes -f %m.
if db_mtime=$(stat -c '%Y' "${DB_FILE}" 2>/dev/null); then
  :
else
  db_mtime=$(stat -f '%m' "${DB_FILE}")
fi

now=$(date +%s)
age_seconds=$((now - db_mtime))
age_hours=$((age_seconds / 3600))

echo "Found cached Trivy DB (age: ${age_hours}h)."

# Seconds, not hours: truncation would allow 59 extra minutes.
if [ "${age_seconds}" -le $((STALE_HOURS * 3600)) ]; then
  echo "::warning::Using cached Trivy vulnerability database (${age_hours} hours old, within ${STALE_HOURS}h bound)."
  summary "**Warning:** Using cached vulnerability database (${age_hours} hours old)." \
    "Database refresh failed; proceeding with stale DB."
  exit 0
fi

echo "::error::Cached Trivy DB is ${age_hours} hours old, exceeding the ${STALE_HOURS}h staleness bound."
summary "**Error:** Cached vulnerability database is ${age_hours} hours old, exceeding the ${STALE_HOURS}h bound." \
  "No fresh DB could be fetched and the cached DB is too stale to trust."
exit 1
