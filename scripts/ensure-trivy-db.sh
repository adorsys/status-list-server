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
# actions/cache restores/saves. It must be absolute: Trivy does not expand
# `~`. The staleness bound is the maximum age of a cached DB before a fetch
# failure becomes fatal instead of a loud warning + stale scan.
#
# Exit codes:
#   0 = DB refreshed, or stale DB accepted with warning
#   1 = fetch failed and no cached DB within the bound (hard failure)

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

# Trivy keeps exactly one DB per cache dir: <cache-dir>/db/trivy.db, with
# metadata.json beside it. A scan with --skip-db-update refuses to run if
# either is missing, so both are required for the cached DB to count.
DB_FILE="${CACHE_DIR}/db/trivy.db"
META_FILE="${CACHE_DIR}/db/metadata.json"

summary() {
  {
    echo "### Trivy vulnerability database"
    echo
    printf '%s\n' "$@"
  } >> "${GITHUB_STEP_SUMMARY:-/dev/null}"
}

# Trivy downloads into a temp dir before touching the cache dir, so a failed
# fetch leaves any cached DB intact for the fallback below.
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

# GNU stat takes -c '%Y'; BSD/macOS stat takes -f '%m'. `-printf` on find is
# GNU-only too, which is why the DB path is fixed rather than searched for.
if db_mtime=$(stat -c '%Y' "${DB_FILE}" 2>/dev/null); then
  :
else
  db_mtime=$(stat -f '%m' "${DB_FILE}")
fi

now=$(date +%s)
age_seconds=$((now - db_mtime))
age_hours=$((age_seconds / 3600))

echo "Found cached Trivy DB (age: ${age_hours}h)."

# Compared in seconds: truncated hours would accept a DB up to 59 minutes past
# the bound.
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
