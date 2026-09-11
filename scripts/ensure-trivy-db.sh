#!/usr/bin/env bash
# ensure-trivy-db.sh -- refresh or degrade the Trivy vulnerability database.
#
# This script is shared between deploy.yml's scan-image job and
# scheduled-image-scan.yml's rescan job so both workflows make the same
# freshness decision from the same code. It must stay in sync with the
# cache-key strategy used in those workflows.
#
# Usage: ensure-trivy-db.sh <cache-dir> <staleness-bound-hours>
#
# The cache directory is the Trivy cache dir (TRIVY_CACHE_DIR) that
# actions/cache restores/saves. The staleness bound is the maximum age
# of a cached DB before a fetch failure becomes fatal instead of a
# loud warning + stale scan. 24h matches Trivy's own up-to-date threshold.
#
# Exit codes:
#   0 = DB refreshed, or stale DB accepted with warning
#   1 = no DB available and fetch failed (hard failure)

set -euo pipefail

CACHE_DIR="${1:-}"
STALE_HOURS="${2:-24}"

if [ -z "${CACHE_DIR}" ]; then
  echo "::error::ensure-trivy-db.sh: cache-dir argument required"
  exit 1
fi

if [ ! -d "${CACHE_DIR}" ]; then
  mkdir -p "${CACHE_DIR}"
fi

DB_DIR="${CACHE_DIR}/db"

# Attempt to download/update the vulnerability DB.
# trivy image --download-db-only pulls the DB into the cache dir without scanning.
# It returns 0 on success, non-zero on failure.
echo "Refreshing Trivy vulnerability database..."
if trivy image --download-db-only --cache-dir "${CACHE_DIR}" 2>&1; then
  # Success: DB is fresh. Report freshness in the summary.
  {
    echo "### Trivy vulnerability database"
    echo
    echo "Database refreshed successfully."
  } >> "${GITHUB_STEP_SUMMARY:-/dev/null}"
  exit 0
fi

# Fetch failed. Check whether we have a usable cached DB.
echo "::warning::Failed to refresh Trivy vulnerability database; checking for cached DB..."

# The vulnerability DB lives in ${DB_DIR}/<schema>/trivy.db (or similar).
# We look for any trivy.db file under the cache dir.
if [ -d "${DB_DIR}" ] && find "${DB_DIR}" -name 'trivy.db' -type f | grep -q .; then
  # Found a cached DB. Compute its age.
  # We take the newest trivy.db as the effective DB.
  newest_db=$(find "${DB_DIR}" -name 'trivy.db' -type f -printf '%T@ %p\n' | sort -nr | head -1 | cut -d' ' -f2-)
  if [ -n "${newest_db}" ]; then
    db_mtime=$(stat -c '%Y' "${newest_db}")
    now=$(date +%s)
    age_seconds=$((now - db_mtime))
    age_hours=$((age_seconds / 3600))

    echo "Found cached Trivy DB (age: ${age_hours}h)."

    if [ "${age_hours}" -le "${STALE_HOURS}" ]; then
      # Within staleness bound: warn but proceed.
      echo "::warning::Using cached Trivy vulnerability database (${age_hours} hours old, within ${STALE_HOURS}h bound)."
      {
        echo "### Trivy vulnerability database"
        echo
        echo "**Warning:** Using cached vulnerability database (${age_hours} hours old)."
        echo "Database refresh failed; proceeding with stale DB."
      } >> "${GITHUB_STEP_SUMMARY:-/dev/null}"
      exit 0
    else
      # Beyond staleness bound: hard fail.
      echo "::error::Cached Trivy DB is ${age_hours} hours old, exceeding the ${STALE_HOURS}h staleness bound."
      {
        echo "### Trivy vulnerability database"
        echo
        echo "**Error:** Cached vulnerability database is ${age_hours} hours old, exceeding the ${STALE_HOURS}h bound."
        echo "No fresh DB could be fetched and the cached DB is too stale to trust."
      } >> "${GITHUB_STEP_SUMMARY:-/dev/null}"
      exit 1
    fi
  fi
fi

# No cached DB at all and fetch failed: hard failure.
echo "::error::No Trivy vulnerability database available and download failed."
{
  echo "### Trivy vulnerability database"
  echo
  echo "**Error:** No vulnerability database available and download failed."
  echo "The scan cannot proceed without a database."
} >> "${GITHUB_STEP_SUMMARY:-/dev/null}"
exit 1