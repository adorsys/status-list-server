#!/bin/sh
# Prove the vulnerability gate fails on a CRITICAL fixture and passes a clean one.
# No network or image needed. Run from the repo root.
set -eu

fixture=scripts/testdata/gate-selftest-findings.json
clean=scripts/testdata/gate-clean-findings.json

for f in "$fixture" "$clean"; do
    [ -f "$f" ] || {
        echo "::error::Gate self-test fixture $f is missing; the gate is unverified."
        exit 1
    }
done

expected=$(jq -r '.Results[]?.Vulnerabilities[]?.VulnerabilityID' "$fixture" | head -1)
if [ -z "$expected" ]; then
    echo "::error::Gate self-test fixture $fixture contains no findings; it cannot test anything."
    exit 1
fi

if output=$(sh scripts/vuln-gate.sh "$fixture" 2>&1); then
    echo "::error::Gate self-test passed against a fixture containing a CRITICAL finding. The vulnerability gate cannot fail and is not protecting this release."
    exit 1
fi

case "$output" in
    *"$expected"*)
        echo "gate self-test: ${expected} correctly fails the gate" ;;
    *)
        echo "::error::Gate self-test exited non-zero but never reported ${expected}, so the gate is erroring rather than blocking. Output follows."
        echo "$output"
        exit 1 ;;
esac

if ! sh scripts/vuln-gate.sh "$clean" > /dev/null 2>&1; then
    echo "::error::Gate self-test failed against a clean fixture. The gate blocks unconditionally and no release can pass it."
    exit 1
fi
echo "gate self-test: clean report correctly passes the gate"
