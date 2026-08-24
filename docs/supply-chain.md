# Container Supply Chain

This document covers how the container image is scanned, what metadata it carries, and how maintainers triage findings. The pipeline is `.github/workflows/deploy.yml`.

## What Runs

`deploy.yml` triggers on **release tags (`v*.*.*`) and manual dispatch only** — not on pushes to `main`, and not on pull requests. A two-architecture build plus scan costs roughly 40 minutes and publishes to GHCR, which is not worth spending on every merge. The consequence is that the image is scanned **once per release**, and that consequence is load-bearing for several of the [Known Gaps](#known-gaps) below.

`build-and-push` builds the multi-architecture image, pushes it to GHCR under the immutable `sha-<short>` tag only, and attaches an SBOM and SLSA provenance. `scan-image` then inspects that image by digest. `promote-tags` applies the semver and `latest` tags to the same digest after the scan. `deploy` runs last and deploys **the same digest** that was scanned.

A dispatch run exercises the build, the scan and every assertion without releasing: `promote-tags` and `deploy` both require `github.event_name == 'push'`, so a dispatch promotes nothing and deploys nothing even when aimed at a tag ref. It does still push `sha-<short>` to GHCR — it publishes an image, it just never advertises or ships one.

The image is pushed before it can be scanned. That is not a tradeoff, it is a constraint: BuildKit attestations can only be produced when pushing directly to a registry, because the local image store cannot hold an image carrying attestations. What the pipeline controls is not whether the artifact exists in GHCR, but what it is *called*. An image that has not passed the scan is reachable only by its commit SHA tag. It never becomes `latest`, never becomes `v1.2.3`, and never reaches production.

That distinction matters more than it first appears. Blocking only the deploy would still leave `latest` and the semver tags resolving to a rejected artifact, so every consumer that is not this pipeline — anything pulling `latest`, any other chart, any developer running `docker pull` — would receive precisely the image the scan refused. Withholding the tags is what makes the refusal mean anything outside this workflow.

`scan-image` runs one scan and derives every view from it:

| Step                     | Severities     | Unfixed  | Ignore file   | Fails the job          | Output                               |
| ------------------------ | -------------- | -------- | ------------- | ---------------------- | ------------------------------------ |
| Resolve arch manifest    | n/a            | n/a      | n/a           | Yes                    | `SCAN_REF`                           |
| Scan image               | All            | Included | Not applied   | No                     | `trivy-image-report.json`            |
| Derive reports           | All / HIGH+    | Included | Gate set only | No                     | `.txt`, two gate sets                |
| Collect published SBOMs  | n/a            | n/a      | n/a           | After 3 failed fetches | `sbom-amd64.json`, `sbom-arm64.json` |
| Job summary + artifacts  | n/a            | n/a      | n/a           | No (`if: always()`)    | Summary, run artifacts               |
| Assert SBOMs list crates | n/a            | n/a      | n/a           | Yes                    | None                                 |
| Prove the gate can fail  | n/a            | n/a      | n/a           | Yes                    | None                                 |
| Vulnerability gate       | HIGH, CRITICAL | Included | Applied       | Yes                    | Blocking + suppressed counts         |

`Derive reports` produces two HIGH/CRITICAL sets: `trivy-highcrit-all.json` before the exception ledger and `trivy-gate-findings.json` after it. The gate reports the difference, so a green result distinguishes "nothing was found" from "everything found was accepted".

Three properties of that ordering are deliberate.

The scan runs before the SBOM fetch. Registry metadata is a separate failure domain from the scan, and when the fetch ran first a transient `imagetools` error left the job with no trivy reports to upload at all — so the run failed twice and produced nothing, in exactly the situation this document tells a responder to go and read the artifacts.

Reports and artifacts are published *before* any assertion runs, and both carry `if: always()`, so a failing assertion still leaves a maintainer with the full report to triage. They upload as two artifacts rather than one: `container-scan-reports` insists its files exist, while `container-sboms` does not, so a lost SBOM cannot take the scan results down with it.

And every view is derived from one scan by `trivy convert` rather than by re-scanning, so the table a maintainer reads and the set the gate evaluates are provably the same data. The gate renders its table from `trivy-gate-findings.json` itself rather than re-applying the same filter to the full report, so the count in the summary, the table in the log, and the exit code cannot disagree about what blocks.

### The Gate Blocks

Any HIGH or CRITICAL finding that survives the exception ledger fails `scan-image`, which withholds the release tags and production.

`ignore-unfixed` is off. That flag exists to mute distro base-image noise, and there is no distro here — the runtime image is `FROM scratch`. The single justification for the flag does not apply, and leaving it on would suppress exactly the class most worth a human decision: a fresh CRITICAL in a crate before upstream ships a fix.

These thresholds do not match the `trivy-config` job in `CI.yml`. That job keeps Trivy's default unfixed handling for Helm misconfigurations; this one deliberately surfaces unfixed crate advisories, for the reason above.

#### The blast radius was measured before this was enabled

Turning `ignore-unfixed` off makes this the first configuration in which the real HIGH/CRITICAL surface is visible, so enabling it blind would risk a release path that is dead on arrival. It was not enabled blind. The surface was measured first, and it is **zero**:

```console
$ trivy fs --scanners vuln --list-all-pkgs --format json --output pk.json .
$ jq '[.Results[]?.Packages[]?] | length' pk.json
663
$ jq -r '[.Results[]?.Vulnerabilities[]?.Severity] | group_by(.) | map({(.[0]): length}) | add // "none"' pk.json
none
```

`Cargo.lock` is a sound upper bound on what the image can contain. The runtime image is `FROM scratch` holding one static binary, a CA bundle and passwd entries, so it has no OS package database; every package a scanner can find in it comes from the `.dep-v0` section, and that section records a *subset* of the lockfile — only the crates actually linked for the enabled feature set. A clean lockfile therefore implies a clean image.

That bound was then confirmed against a real build rather than left as an argument. Scanning the built image directly:

```console
$ trivy image --input image.tar --scanners vuln --list-all-pkgs --format json --output full.json
$ jq -r '.Results[]? | "\(.Target) type=\(.Type) pkgs=\(.Packages|length)"' full.json
app/status-list-server type=rustbinary pkgs=469
$ jq -r '[.Results[]?.Vulnerabilities[]?.Severity] | group_by(.) | map({(.[0]): length}) | add // "none"' full.json
none
```

The three package counts differ, and the ordering is the point:

| Source                          | Count | Why                                   |
| ------------------------------- | ----- | ------------------------------------- |
| `Cargo.lock`                    | 663   | every crate, all features and targets |
| `.dep-v0` via `rust-audit-info` | 521   | crates linked in, runtime and build   |
| Trivy reading the image         | 469   | the runtime set the scanner evaluates |

`663 ⊇ 521 ⊇ 469`, which is what makes the lockfile a valid stand-in when no image exists yet. It also means the build assertion and the scanner are counting different things by design: the assertion only needs to prove the section is present and non-empty.

A zero from a scanner is only worth as much as the scanner's ability to return non-zero, so that was checked too, against a fixture containing the same crate versions plus two known-vulnerable ones:

```console
$ trivy fs --scanners vuln --format json --output f.json .
CRITICAL  CVE-2021-25900  smallvec 1.6.0
MEDIUM    CVE-2020-26235  time 0.1.44
```

`rsa 0.9.10` and `rkyv 0.7.46` — the two advisories `deny.toml` currently ignores — produce nothing in that same fixture, which is why they need no entry in `.trivyignore.yaml`. See [Two Ledgers](#two-ledgers).

#### Every release proves the gate can still fail

A clean scan is the expected result on every run, and that is the problem: a gate that has never fired is indistinguishable from a gate that cannot fire. Both print nothing and exit zero.

So `scan-image` runs a self-test immediately before the gate. It invokes `scripts/vuln-gate.sh` — the same script, the same flags and the same `trivy` binary the real gate uses one step later — against two fixtures, and requires both directions to hold:

- `scripts/testdata/gate-selftest-findings.json` holds one CRITICAL finding and **must** fail the gate. If it does not, the job fails with "the vulnerability gate cannot fail and is not protecting this release".
- `scripts/testdata/gate-clean-findings.json` holds none and **must** pass. A gate that blocks unconditionally is equally broken, and without this it would only surface mid-release.

A non-zero exit is necessary but not sufficient evidence, which the first version of this step got wrong. A missing fixture, a `trivy` that is not on `PATH`, and a malformed report all exit non-zero too, so checking only the exit status meant a fixture that was never committed would have read as a *passing* self-test — the absence-reads-as-success failure this step exists to prevent, occurring inside it. The step therefore also asserts the fixture exists and holds at least one finding, and requires the gate's output to name the vulnerability ID it was given. Only a gate that actually evaluated the report can print that ID back.

Those four conditions are each exercised by breaking them: fixture removed, fixture emptied, gate forced to `--exit-code 0`, and gate replaced with a bare `exit 1`. All four fail the step, with distinct messages.

The gate is a script rather than an inline step for exactly this reason. Inline, the self-test and the gate would be two copies of a flag list that must not drift, and the drift would be undetectable: a self-test passing against different flags than the real gate uses tells you nothing about the real gate.

### Where Results Go

Results land in two places, with different lifetimes:

- **The job summary**, for the run you are looking at. Truncated at 900 KB because step summaries are capped at 1 MiB.
- **Run artifacts**, in two parts: `container-scan-reports` (the unfiltered JSON, the table, and both gate sets) and `container-sboms`. Both expire with the repository's artifact retention (90 days by default).

**There is no GitHub code scanning sink for image scans.** That is a consequence of the trigger, not an oversight: this workflow runs only on `refs/tags/*`, and code scanning files an analysis against a ref, so alerts for a tag are not surfaced in the Security tab's branch view. An upload would succeed into a place nobody reads, which looks like coverage without being any — the failure mode the rest of this pipeline exists to eliminate. Emitting a SARIF nothing consumes would be the same thing one step earlier, so `scan-image` does not produce one at all.

If you want SARIF from a run, derive it from the artifact — Trivy converts the report that is already kept:

```bash
trivy convert --format sarif --output image.sarif trivy-image-report.json
```

Every scan result therefore lives only as long as artifact retention. Giving image findings a durable, alerting home needs a scheduled workflow that scans the deployed digest and uploads against the default branch, not a release pipeline; see [Known Gaps](#known-gaps).

Helm and workflow findings are unaffected — `kube-linter` and `zizmor` upload SARIF from `CI.yml`, which does run on branches and pull requests.

### The Scanned Artifact Is the Deployed Artifact

The scan binds to `...@sha256:<digest>`. `promote-tags` retags that same digest, and the deploy passes it to the chart via `statuslist.image.digest`, which `helm/chart/templates/deployment.yaml` prefers over `statuslist.image.tag`. Tags stay in place for readability but no longer determine what runs.

This matters because tags are mutable. Binding the scan to a digest and then deploying by tag would leave a window in which a re-run or a manual push could replace the image in between.

Two `concurrency` groups back that up. The workflow-level group is keyed on the ref, so re-runs of the same tag do not overlap. The `deploy` job declares a second one keyed on `deploy-production`, because two tags pushed in quick succession are *different* refs and the workflow-level group would let both drive `helm upgrade --atomic` against the same release at once. What guarantees production runs the scanned artifact is the digest binding; what the second group prevents is two deploys racing for the Helm release lock.

### Which Architecture Is Scanned

The pushed digest names a multi-platform *index*, not an image. Scanning the index directly would leave the choice of platform to Trivy's own default, so `scan-image` resolves the child manifest first: it reads the index with `docker buildx imagetools inspect --raw`, selects the single `linux/amd64` entry, and scans `repo@<manifest-digest>`.

This replaced an earlier design that scanned the index with `TRIVY_PLATFORM` set and then asserted the scanned architecture afterwards. That assertion could not fail. Trivy's default on an `ubuntu-latest` runner is already `amd64`, so the check passed identically whether or not the requested platform had any effect — it read as verification while proving nothing, which is the exact failure mode the rest of this pipeline is built to eliminate. Resolving the manifest makes the property true by construction, so there is nothing left to assert.

The resolution step *does* fail if the index does not contain exactly one `linux/amd64` manifest, which is a real condition with a real cause: the build stopped producing the platform this pipeline claims to scan.

## Why the Image Must Be Self-Describing

The runtime image is `FROM scratch` and contains one statically linked musl binary, CA certificates, and passwd entries. There is no OS package database and no dependency manifest.

Scanning that image with stock settings enumerates zero packages. The scan passes, the SBOM is a well-formed empty document, and nothing is actually verified. Every acceptance check goes green while security posture is unchanged.

With `cargo-auditable` it enumerates 469, reported by Trivy against a target of type `rustbinary`. That number is the difference between this pipeline working and this pipeline being theatre, which is why two independent assertions defend it: the build-stage check that the section decodes non-empty, and the published-SBOM check that the attached SBOM lists `pkg:cargo/` purls.

`cargo-auditable` is the mechanism that fixes this. It records the dependency graph as compressed JSON in a linker section named `.dep-v0`. Per the [cargo-auditable README](https://github.com/rust-secure-code/cargo-auditable), the section is read automatically by Trivy from v0.31.0, Grype from v0.83.0, Syft from v1.15.0 (older Syft needs `--catalogers all`), and osv-scanner from v2.0.1. Syft deliberately does not fall back to cataloguing `Cargo.lock` during image scans, because a lockfile inside an image is not guaranteed to describe the binary next to it, so there is no source-side substitute for embedding the data.

The release profile in `Cargo.toml` sets `strip = true`, `lto = true`, and `codegen-units = 1`. Each of those can independently drop an unreferenced section, and `cargo-auditable` relies on `#[used]` to prevent it. Rather than depend on that holding across toolchain versions, the builder stage runs `rust-audit-info` on the binary immediately before it is copied into the scratch stage.

That assertion checks two things, not one. It checks that the section **decodes**, and that it decodes to a **non-empty** package list. Decoding an empty dependency graph exits zero, so an exit-status check alone would pass on exactly the empty-but-present artifact the assertion exists to catch.

That assertion is permanent by design. The failure it guards against looks exactly like success, so a one-time check would only prove the property held on the day someone looked.

The build assertion covers the binary. It says nothing about the SBOM BuildKit attaches, which is a different artifact produced by a different tool — if BuildKit's bundled Syft were older than v1.15.0, the assertion would pass and an empty SBOM would still ship. `scan-image` therefore closes the chain from the other end: it pulls the published SBOM **for both platforms** and fails unless each lists at least one `pkg:cargo/` purl. Both, because whether BuildKit's cataloguer ran is a per-platform property, and the binary assertion is not evidence about it in either direction. It asserts a cargo purl rather than a package count because SPDX output includes a synthetic package describing the image itself, which would satisfy a bare "not empty" check on nothing, and it deduplicates the purls because each appears in both `externalRefs` and `relationships`.

## Never Pass Secrets as Build Arguments

`deploy.yml` builds with `provenance: mode=max`. `mode=max` records the full build invocation in the provenance attestation, and that includes **every `build-arg` value**. The attestation is published alongside the image and is readable by anyone who can pull it.

So a secret passed as a build argument is not merely present in an image layer, which is the failure people usually have in mind — it is published as structured metadata, permanently, in a document this pipeline actively asserts the presence of. Nothing in the build will look wrong, and the review diff for adding it is one plausible-looking line.

The build arguments used today are `APP_NAME`, `FEATURES`, `CARGO_AUDITABLE_VERSION`, and `RUST_AUDIT_INFO_VERSION`; all four are non-sensitive by construction, and the list should stay that way. If a build ever needs a credential — a private registry token, a licence key — use a BuildKit secret mount instead, which is not recorded in provenance:

```dockerfile
RUN --mount=type=secret,id=token \
    TOKEN="$(cat /run/secrets/token)" ...
```

```yaml
- uses: docker/build-push-action@...
  with:
    secrets: |
      token=${{ secrets.SOME_TOKEN }}
```

Dropping to `provenance: mode=min` would also hide build args, at the cost of the build detail that makes the provenance worth publishing. Use the secret mount; keep `mode=max`.

## Verifying Locally

Resolve the same architecture manifest CI scans, then reproduce the gate against it. `--exit-code 1` is what CI uses, so this exits non-zero on exactly the findings that would block a release. Scanning the resolved manifest rather than the index is what makes this reproduce CI instead of approximating it:

```bash
index=ghcr.io/adorsys/status-list-server@sha256:<index-digest>

manifest=$(docker buildx imagetools inspect --raw "$index" \
  | jq -r '.manifests[]
           | select(.platform.os == "linux" and .platform.architecture == "amd64")
           | .digest')

trivy image \
  --severity HIGH,CRITICAL \
  --ignorefile .trivyignore.yaml \
  --exit-code 1 \
  "ghcr.io/adorsys/status-list-server@${manifest}"
```

Before a release exists, `Cargo.lock` answers the same question and needs no build. It is a sound upper bound on the image, for the reason given above, so a clean result here means the gate will pass:

```bash
trivy fs --scanners vuln --severity HIGH,CRITICAL --exit-code 1 .
```

Check the gate wiring itself the way CI does, which needs no network and no image:

```bash
sh scripts/vuln-gate.sh scripts/testdata/gate-selftest-findings.json   # must exit 1
sh scripts/vuln-gate.sh scripts/testdata/gate-clean-findings.json      # must exit 0
```

`local-ci.sh` runs both, along with the `.trivyignore.yaml` validator and its tests.

Inspect the attached metadata. Both fields are keyed by platform, so index into them rather than dumping the whole map:

```bash
docker buildx imagetools inspect ghcr.io/adorsys/status-list-server:<tag> \
  --format '{{ json (index .SBOM "linux/amd64") }}'

docker buildx imagetools inspect ghcr.io/adorsys/status-list-server:<tag> \
  --format '{{ json (index .Provenance "linux/amd64") }}'
```

Confirm the shipped binary carries audit data. An SBOM that lists no crates almost always means this section is missing:

```bash
id=$(docker create ghcr.io/adorsys/status-list-server:<tag>)
docker cp "$id:/app/status-list-server" ./status-list-server
docker rm "$id"
rust-audit-info ./status-list-server
```

Reproduce the build assertion without Docker. This has to match what the `Dockerfile` actually does — the same pinned tool versions, the same lockfile enforcement, the same target, and the same feature set — or the result does not reproduce the build:

```bash
cargo install --locked --version 0.7.5 cargo-auditable
cargo install --locked --version 0.5.4 rust-audit-info

rustup target add x86_64-unknown-linux-musl
cargo auditable build --locked --release \
  --target x86_64-unknown-linux-musl \
  --features "postgres,aws-secrets,acme"

rust-audit-info target/x86_64-unknown-linux-musl/release/status-list-server \
  | jq '.packages | length'
```

A count of `0` is the failure the build assertion catches.

Check the published SBOM the way CI does, for both platforms:

```bash
for platform in linux/amd64 linux/arm64; do
  docker buildx imagetools inspect ghcr.io/adorsys/status-list-server:<tag> \
    --format "{{ json (index .SBOM \"$platform\") }}" \
    | jq --arg p "$platform" \
        '[.. | strings | select(startswith("pkg:cargo/"))] | unique | length
         | "\($p): \(.) distinct cargo packages"'
done
```

## Triaging a Finding

1. Read the full report artifact from the workflow run, not just the gate output. The gate applies a severity floor and the exception ledger; the artifact does not.
2. Confirm the finding applies. Check whether the advisory affects the feature set this image is built with (`postgres,aws-secrets,acme` — the `ARG FEATURES` default in the `Dockerfile`) and whether the vulnerable code path is reachable.
3. Look for a fixed version. Most findings resolve with `cargo update -p <crate>` or by taking the Dependabot PR.
4. If a fix exists and can be taken, take it. Do not add an exception for a finding you could simply fix.
5. If a fix exists but cannot be taken yet, or no fix exists, or the finding does not apply to this build, add an exception with a `statement` recording which of those three it is.

### Accepting an Exception

Exceptions live in `.trivyignore.yaml` under `vulnerabilities`, alongside the existing Helm misconfiguration entries. Each entry needs a `statement` explaining why the finding is accepted and what would change that, and an `expired_at` date:

```yaml
vulnerabilities:
  - id: RUSTSEC-0000-0000
    statement: Advisory affects the async runtime path; this binary only uses the blocking API.
    expired_at: 2026-01-01
```

`expired_at` is what keeps the ledger honest. Without it, an exception taken once becomes permanent and nobody revisits it. When an entry expires the finding reappears and must be re-argued.

These fields are enforced, not merely documented. `scripts/check-trivyignore.py` runs in the `trivy-config` job before Trivy reads the file, and in `local-ci.sh`. It rejects invalid YAML, unknown top-level sections (a section named `vulnerability` parses fine and suppresses nothing), entries with no `id`, entries with no `statement`, vulnerability entries with no `expired_at`, and malformed dates. An already-expired entry is reported as a warning rather than an error: it has stopped suppressing anything, so it is dead configuration rather than a broken gate.

The validator has its own tests in `scripts/tests/`, which CI runs before the validator itself. An untested validator guarding an ignore file has the same problem as an untested vulnerability gate: it looks identical whether it works or does nothing.

It also rejects **unknown keys inside an entry**, which is the check that matters most and the least obvious. Trivy silently ignores keys it does not recognise, so a one-character typo is a scope change rather than an error: `path:` instead of `paths:` leaves the entry with no path filter, and an entry with no path filter applies everywhere. Measured against this chart, that typo takes `KSV-0014` from 8 remaining findings to 0 — an exception written to cover one vendored subchart silently starts suppressing the rule repository-wide, and both the file and the scan still look correct.

The same widening is reachable by simply **omitting** `paths`, so misconfiguration entries are required to carry a non-empty `paths` or `purls` list. Catching the typo but not the omission would leave the easier route open. Vulnerability entries are exempt from that requirement: a `FROM scratch` image holding one binary has no meaningful path to scope a crate advisory to, so an unscoped entry is the intended form there and demanding `paths: ['**']` would be noise. Where either key *is* present, in any section, it must be a non-empty list of non-empty strings — `paths: []` is unscoped just as surely as no `paths` at all.

Duplicate IDs are deliberately *not* rejected: the same rule legitimately appears more than once when it is scoped to different `paths`.

### Two Ledgers

This repository now suppresses crate advisories in two places, and they are not connected:

|                      | `deny.toml` `[advisories] ignore`   | `.trivyignore.yaml` `vulnerabilities`      |
| -------------------- | ----------------------------------- | ------------------------------------------ |
| Read by              | `cargo-deny`, on every pull request | `trivy`, on releases and in `trivy-config` |
| Applies to           | the dependency graph                | the built image                            |
| Reason recorded      | free-text comment                   | `statement` field                          |
| Expires              | no                                  | yes, `expired_at` required                 |
| Enforced             | no                                  | `scripts/check-trivyignore.py` (tested)    |
| Suppressions visible | no                                  | counted in every gate summary              |

Today `deny.toml` ignores `RUSTSEC-2023-0071` (rsa) and `RUSTSEC-2026-0235` (rkyv), and `.trivyignore.yaml` ignores neither, because Trivy's database does not flag either at the versions this project pins — verified, not assumed. So the two ledgers do not currently disagree.

They can, and the failure is asymmetric in an unhelpful direction. If Trivy's database later picks up one of those advisories at HIGH or above, a release blocks on something `cargo-deny` has been deliberately ignoring for months, and the person cutting the release has to rediscover an argument that already exists in `deny.toml`. In the other direction, someone who fixes `rsa` and removes the `deny.toml` entry has no prompt to check whether a `.trivyignore.yaml` entry also became stale.

When adding to either ledger, check the other. Consolidating them is not currently possible — the two tools do not share a format — so this is a coordination cost, not a bug to fix.

### Field Rules

`expired_at` is required under `vulnerabilities` but not under `misconfigurations`. A vulnerability exception is a claim about a changing world — whether a fix exists, whether the vulnerable path is reachable — so it rots and has to be re-argued. A misconfiguration exception here is a claim about a structural fact, that a path belongs to a third-party subchart this repository does not author, which does not rot on a schedule. Both still require a `statement`.

Be aware of the timing that creates: once the gate is enabled, an expiry surfaces as a **blocked release**, because that is the only moment this pipeline runs. Until the scheduled re-scan ([#410](https://github.com/adorsys/status-list-server/issues/410)) exists, prefer expiry dates that do not fall close to a planned release, and re-argue entries proactively rather than waiting for them to fire.

This file is read by two consumers on different cadences — the `trivy-config` job in `CI.yml` on every pull request, and the image scan on releases. A malformed entry added here under incident pressure breaks pull request CI for the whole repository, not just the release path.

## Tool Ownership

`cargo-auditable` and `rust-audit-info` are pinned in the `Dockerfile` as build arguments. Those pins are invisible to every Dependabot ecosystem configured in this repository: the `cargo` ecosystem reads `Cargo.toml` and `Cargo.lock`, the `docker` ecosystem reads `FROM` tags, and neither parses `RUN` arguments. Dependabot has no regex-based manager that could be pointed at them. Nothing will open a bump PR for them and nothing will report them as stale.

`rust-toolchain.toml` is `channel = "stable"`, so the toolchain moves on its own without any file changing. `cargo-auditable` wraps rustc, which makes the coupling a runtime property rather than a compile-time one, so drift surfaces without a triggering commit.

The symptom is a builder-stage failure in the deploy path, either at the `cargo install` layer or at the `rust-audit-info` assertion, on a commit that changed nothing relevant. That is the intended outcome: a loud build failure instead of a silently empty SBOM. Bump both pins against crates.io when it happens, or opportunistically during unrelated `Dockerfile` work.

This is an accepted gap rather than a solved problem. It was considered and rejected to add a scheduled job that polls crates.io and opens an issue: an unmonitored automation that fails silently is indistinguishable from one with nothing to report, which is the same trap this pipeline is built to avoid. The current failure is bad but legible. If this repository later adopts Renovate, its regex manager can read these pins without any workflow at all, and that is the right time to close this.

## Relationship to Source-Level Checks

`cargo-audit`, `cargo-deny`, and `cargo-vet` already query RustSec against the dependency tree on every pull request. The image scan queries the same advisory database, so it will rarely surface a crate advisory that source-level CI did not.

What it adds today is narrower than that overlap suggests:

- The SBOM describes the artifact that ships, not the source tree it was built from, and is published with the image for downstream consumers.
- It detects drift if the image was built from a lockfile that source-level CI never audited.
- It binds a scan result to an image digest, so what was checked and what runs are the same artifact.

There is one further capability often claimed for a setup like this — catching advisories published *after* merge, with no source change — and this pipeline does **not** deliver it. `deploy.yml` triggers only on release tags and on manual dispatch, so the image scan runs **once per release** and never again for that image. A newly published advisory first surfaces whenever someone next cuts a release, which may be weeks later and is not tied to the advisory at all.

The source-level checks are what actually run continuously here: `cargo-audit`, `cargo-deny`, and `cargo-vet` query RustSec on every pull request. They cover the dependency tree rather than the artifact, so they will usually see a crate advisory first — but only when something triggers CI. Neither path notices an advisory published against an already-released image while nobody is pushing code. Closing that needs a scheduled re-scan of the deployed digest, tracked in [#410](https://github.com/adorsys/status-list-server/issues/410).

Findings about crates belong to `cargo-audit` and are fixed at the lockfile. Findings about the image belong here.

### The Release Feature Set

Source-level CI compiles two feature sets: `--all-features`, and `--no-default-features --features memory`. The image is built with neither. Its `ARG FEATURES="postgres,aws-secrets,acme"` names a combination that was reachable from no CI job at all.

Nothing validated that string. `ARG FEATURES` is a bare string handed to `cargo build` inside the image build, so a value naming no real feature is caught only when someone cuts a release — and it had one. The value was `postgres,aws,acme`, and `Cargo.toml` defines `aws-secrets`, not `aws`, so `cargo` would have rejected it outright.

`--all-features` does not stand in for the real set either. Cargo unifies features across the dependency graph, so enabling every feature of this crate compiles its shared dependencies with the union of theirs: `--all-features` turns on `postgres`, `sqlite`, and `mysql` together and builds `sea-orm` with all three `sqlx` backends, where the release set builds it with `sqlx-postgres` alone. The secret backends behave the same way — `--all-features` compiles `vault`, `gcp-secrets`, `azure-kv`, and `aws-secrets` at once; the image ships `aws-secrets` by itself.

This is the shape worth remembering: **enabling every feature is not a superset of shipping some of them.** Unification builds the graph differently, and `#[cfg(not(...))]` branches exist only in the absence of a feature — so `--all-features` is its own configuration, not an upper bound on the ones you ship.

`cargo-build` now runs a `Release image feature set` step that reads `ARG FEATURES` out of the `Dockerfile` and checks that combination, so the release build's feature set is verified on every pull request rather than at release time. Reading it from the `Dockerfile` rather than repeating it is deliberate: a duplicated feature list would drift, and the drift would restore the gap silently.

## Known Gaps

- **Crate advisories are suppressed in two unconnected ledgers**, `deny.toml` and `.trivyignore.yaml`. Nothing keeps them in agreement; see [Two Ledgers](#two-ledgers).
- **The image is scanned once per release and never again.** `deploy.yml` runs only on release tags and manual dispatch, so between releases nothing looks at the running image. This is a deliberate cost decision — see [What Runs](#what-runs) — and it is the single largest gap, because it is the common cause of four others: post-release advisory detection does not work, `expired_at` lapses surface as a blocked release rather than as advance warning, scan results have no durable sink beyond artifact retention, and the builder-stage audit assertion is only exercised on the release path. All of them close together with one scheduled workflow that scans the deployed digest on a cron, uploads SARIF against the default branch, and opens an issue on failure. Tracked in [#410](https://github.com/adorsys/status-list-server/issues/410).
- **Image scan results never reach GitHub code scanning.** Alerts filed against a `refs/tags/*` ref are not surfaced in the Security tab's branch view, so `scan-image` deliberately emits no SARIF rather than uploading into a place nobody reads; see [Where Results Go](#where-results-go). Helm and workflow findings are unaffected — `kube-linter` and `zizmor` upload from `CI.yml`, which runs on branches and pull requests.
- **BuildKit attestations are unsigned** and carry no Sigstore identity, so provenance has no verifiable issuer. It is a record of the build, not evidence about it: anyone with push access to the repository could produce an equivalent document. Adding `actions/attest-build-provenance` is tracked in [#402](https://github.com/adorsys/status-list-server/issues/402), and is not a one-line change — it emits a second provenance document alongside BuildKit's, which forces a decision about keeping both or setting `provenance: false` and giving up the `mode=max` build detail.
- **Only `linux/amd64` is scanned for vulnerabilities.** Both platforms are built from the same lockfile into a scratch image with no OS packages, so their package sets are identical, so scanning one is not expected to differ from scanning both. `scan-image` resolves that architecture's manifest and scans it by digest, so which architecture was scanned is fixed by construction rather than asserted after the fact — see [Which Architecture Is Scanned](#which-architecture-is-scanned). Note this applies to vulnerability scanning only: the published-SBOM assertion covers both platforms, because that check is about whether BuildKit's cataloguer ran, which the package-set argument says nothing about.
- **Gate behaviour is reproducible against a fixed advisory database, not across time.** A finding can move from absent to blocking with no change in this repository. That is intentional — it is how post-merge advisories are meant to reach the gate — but it means "reproducible" holds for a given database snapshot.
- **The Trivy vulnerability database is fetched fresh on every run**, unauthenticated, from a third party, at release time. That makes a network blip or a GHCR rate limit into a failed release, and it surfaces as the security gate failing, which reads as "a vulnerability was found". Tracked in [#405](https://github.com/adorsys/status-list-server/issues/405).
- **The builder-stage audit assertion runs only on the release path.** `deploy.yml` does not run on pull requests, so a change that breaks the auditable build is green on the PR and fails during a release. Tracked against [#316](https://github.com/adorsys/status-list-server/issues/316).
- **An expired ignore entry is a warning, not a failure.** `scripts/check-trivyignore.py` enforces the required fields but only warns when a date has passed, because an expired entry has already stopped suppressing anything. Whether a lapsed entry should block CI is a policy question that belongs with the scheduled re-scan ([#410](https://github.com/adorsys/status-list-server/issues/410)), since that is what would give advance warning before a release hits it.
- **There is no break-glass for the gate.** With `ignore-unfixed` off and any HIGH or CRITICAL blocking, a newly published unfixed advisory in a linked crate makes it impossible to cut *any* release, including a security hotfix for something unrelated. The only path is landing a `.trivyignore.yaml` entry through pull request CI — which is the file this document warns hardest against editing under incident pressure. `workflow_dispatch` deliberately cannot release, so it is not an override. A dispatch input gated on the `production` environment's reviewers, recording the justification in the run summary, would close this; it is a policy decision rather than a mechanical one and has not been made.
