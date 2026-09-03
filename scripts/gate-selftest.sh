#!/bin/sh
# Prove the vulnerability gate can both fail and pass, before trusting its verdict.
#
# A clean scan is the expected result on every run, and that is the problem: a gate
# that has never fired is indistinguishable from a gate that cannot fire. Both print
# nothing and exit zero.
#
# So this runs scripts/vuln-gate.sh -- the same script, flags and trivy binary the
# real gate uses -- against two committed fixtures. One holding a CRITICAL must fail
# the gate; a clean one must pass, because a gate that blocks unconditionally is
# equally broken and would otherwise only surface mid-release.
#
# Exit status alone is not sufficient evidence. A missing fixture, a trivy not on
# PATH and a malformed report all exit non-zero, so checking only the exit code would
# let a fixture that was never committed read as a *passing* self-test -- the
# absence-reads-as-success failure this exists to prevent, occurring inside it. So it
# also asserts the fixture exists, holds at least one finding, and that the gate's
# output names the vulnerability ID it was given back. Only a gate that really
# evaluated the report can print that ID.
#
# Shared by deploy.yml, the scheduled re-scan and local-ci.sh. Three copies would
# drift, and a self-test that has drifted from the gate proves nothing about the gate.
#
# Needs no network and no image: the fixtures are JSON on disk and `trivy convert`
# re-renders a report it is handed. Run from the repository root; takes no arguments.
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

# The other direction: a gate that blocks unconditionally is also broken, and would
# otherwise only surface during a release.
if ! sh scripts/vuln-gate.sh "$clean" > /dev/null 2>&1; then
    echo "::error::Gate self-test failed against a clean fixture. The gate blocks unconditionally and no release can pass it."
    exit 1
fi
echo "gate self-test: clean report correctly passes the gate"
