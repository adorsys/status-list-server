#!/bin/sh
# Render a Trivy gate finding set and fail if it is not empty.
#
# This exists as a script rather than an inline `run:` step so that the release
# gate and the self-test that proves the gate works are provably the same command.
# Inline, they would be two copies of a flag list that must not drift, and the
# drift would be undetectable: a self-test passing against different flags than the
# real gate uses tells you nothing about the real gate.
#
# The input is already filtered -- severity floor and the exception ledger were
# applied when `trivy-gate-findings.json` was produced -- so this deliberately does
# no filtering of its own. Anything present in the input blocks.
set -eu

findings=${1:?usage: vuln-gate.sh <trivy-gate-findings.json>}

trivy convert --format table --exit-code 1 "$findings"
