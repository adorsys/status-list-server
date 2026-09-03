#!/bin/sh
# Derive every view of one architecture's scan from that scan's single JSON report.
#
# This file is the gate configuration. The severity floor and which set the exception
# ledger is applied to are decided here, so changing it changes both what blocks a
# release and what the scheduled re-scan compares against.
#
# Deriving by `trivy convert` rather than re-scanning is what makes the table a
# maintainer reads and the set the gate evaluates provably the same data.
#
# Two HIGH/CRITICAL sets are produced: `trivy-highcrit-all-<arch>.json` before the
# ledger and `trivy-gate-findings-<arch>.json` after it. The difference is what the
# exceptions hid, so a green gate distinguishes "nothing was found" from "everything
# found was accepted".
#
# A script rather than an inline step so the release scan and the scheduled re-scan
# are provably running the same flags; same reasoning as scripts/vuln-gate.sh.
#
# Reads `trivy-image-report-<arch>.json` from the working directory and writes the
# derived files alongside it. Exit status is 0 when every view was produced.
#
# Usage: derive-trivy-reports.sh <arch> [ignorefile]
set -eu

arch=${1:?usage: derive-trivy-reports.sh <arch> [ignorefile]}
ignorefile=${2:-.trivyignore.yaml}

report="trivy-image-report-${arch}.json"

# Without this the convert calls below would fail one by one against a missing file,
# reporting the symptom rather than "linux/<arch> was never scanned".
[ -f "$report" ] || {
    echo "::error::${report} not found; the scan for linux/${arch} produced no report."
    exit 1
}

# trivy-action puts the binary on PATH for later steps; fail loudly rather than
# silently skipping every derived report if that stops being true.
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
