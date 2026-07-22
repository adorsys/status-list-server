#!/bin/bash

# DEPRECATED: Use `cargo xtask ci` instead.
# This script is kept for backward compatibility and will be removed in a future release.

set -e

echo "Running local CI checks via cargo xtask..."
exec cargo xtask ci 