#!/bin/sh
# Fail if the gate findings set is non-empty; the self-test runs this exact command.
# Input is already filtered (severity floor and ledger), so anything present blocks.
set -eu

findings=${1:?usage: vuln-gate.sh <trivy-gate-findings.json>}

trivy convert --format table --exit-code 1 "$findings"
