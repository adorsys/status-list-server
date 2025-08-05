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

echo "✅ All CI checks passed!" 