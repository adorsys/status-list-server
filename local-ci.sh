#!/bin/bash

# Simple local CI script that runs the same commands as GitHub CI
# Run this before pushing to ensure CI will pass

set -e

echo "Running local CI checks..."

# 1. Cargo Format Check (same as CI)
echo "Checking code format..."
cargo fmt --all --check

# 2. Cargo Build (same as CI)
echo "Building project..."
cargo build --workspace --all-targets --all-features

# 3. Cargo Clippy Check (same as CI)
echo "Running clippy..."
cargo clippy --workspace --all-targets --all-features -- -D warnings

# 4. Cargo Nextest (same as CI)
echo "Running tests..."
cargo nextest run --workspace --all-targets --all-features

# 5. Cargo Machete Check (same as CI)
echo "Checking unused dependencies..."
cargo machete --with-metadata

# 6. Trivy ignore-file validation and workflow variant parity (same as CI)
# A malformed .trivyignore.yaml fails the trivy-config job on every open pull
# request, not just yours. The parity check catches a variant added to deploy.yml
# but not to the scheduled re-scan, which otherwise fails nowhere -- the variant is
# just never re-scanned.
echo "Validating .trivyignore.yaml..."
if command -v python3 >/dev/null 2>&1; then
    python3 -m unittest discover -s scripts/tests -p 'test_*.py'
    python3 scripts/check-trivyignore.py .trivyignore.yaml
    python3 scripts/check-variant-parity.py
else
    echo "  skipped: python3 not found"
fi

# 7. Vulnerability gate wiring (needs no network and no image)
echo "Checking vulnerability gate wiring..."
if command -v trivy >/dev/null 2>&1; then
    # The same script CI runs, so this checks the gate the way the release path and
    # the scheduled re-scan do -- including that the gate names the ID it was given,
    # which the previous inline check here did not assert.
    sh scripts/gate-selftest.sh
else
    echo "  skipped: trivy not found"
fi

# 8. Image reference resolution (same as CI)
# The digest branch of the chart's image conditionals is only exercised here; a
# regression means production stops running the digest that was scanned.
echo "Checking image reference resolution..."
if command -v helm >/dev/null 2>&1 && command -v yq >/dev/null 2>&1; then
    helm dependency build helm/chart >/dev/null
    bash scripts/verify-image-reference.sh
else
    echo "  skipped: helm or yq not found"
fi

echo "✅ All CI checks passed!" 