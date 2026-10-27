#!/bin/sh
# Derive every view of one arch's scan from its single report, so the table and the gate read the same data.
# This is the gate config: the severity floor and where the ledger applies live here.
# Usage: derive-trivy-reports.sh <arch> [ignorefile]
set -eu

arch=${1:?usage: derive-trivy-reports.sh <arch> [ignorefile]}
ignorefile=${2:-.trivyignore.yaml}

report="trivy-image-report-${arch}.json"

[ -f "$report" ] || {
    echo "::error::${report} not found; the scan for linux/${arch} produced no report."
    exit 1
}

# Fail loudly if trivy-action stops putting trivy on PATH.
trivy --version > /dev/null

trivy convert --format table --output "trivy-image-report-${arch}.txt" "$report"

trivy convert \
    --severity HIGH,CRITICAL \
    --format json --output "trivy-highcrit-all-${arch}.json" \
    "$report"

trivy convert \
    --severity HIGH,CRITICAL \
    --ignorefile "$ignorefile" \
    --format json --output "trivy-gate-findings-${arch}.json" \
    "$report"

# A clean scan must still produce every artifact.
[ -s "trivy-image-report-${arch}.txt" ] || echo "No vulnerabilities reported." > "trivy-image-report-${arch}.txt"
[ -s "trivy-gate-findings-${arch}.json" ] || echo '{"Results":[]}' > "trivy-gate-findings-${arch}.json"
[ -s "trivy-highcrit-all-${arch}.json" ] || echo '{"Results":[]}' > "trivy-highcrit-all-${arch}.json"
