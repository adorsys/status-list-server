#!/usr/bin/env bash
set -euo pipefail
export NODE_ENV=production
cd deploy/observability/dashboards/src
npm install --no-audit --no-fund --package-lock=false
npm run generate-dashboards
git diff --exit-code ../generated/status-list-slo.json
git diff --exit-code ../../../helm/chart/observability/dashboards/generated/status-list-slo.json
cmp ../generated/status-list-slo.json ../../../helm/chart/observability/dashboards/generated/status-list-slo.json
