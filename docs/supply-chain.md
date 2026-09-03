# Container Supply Chain

The pipeline is `.github/workflows/deploy.yml`. **If a release is blocked and you need to act, read the next section and stop there.** Everything after it is the reasoning behind the design, kept for whoever changes it.

## Operator Guide

**What blocks a release.** Any HIGH or CRITICAL vulnerability that survives `.trivyignore.yaml`, on any published architecture (`linux/amd64`, `linux/arm64`). Unfixed vulnerabilities count. MEDIUM and below are reported but never block.

**Where the evidence is.** On the failed run, in artifacts kept for the repository's retention period (90 days by default):

| You want                             | Artifact                 | File                                      |
| ------------------------------------ | ------------------------ | ----------------------------------------- |
| The exact blocking set               | `container-scan-reports` | `trivy-gate-findings-<arch>.json`         |
| Everything HIGH/CRITICAL, pre-ledger | `container-scan-reports` | `trivy-highcrit-all-<arch>.json`          |
| The full scan, all severities        | `container-scan-reports` | `trivy-image-report-<arch>.json` / `.txt` |
| The published SBOM                   | `container-sboms`        | `sbom-<arch>.json`                        |

Provenance and SBOM are also attached to the image itself: `docker buildx imagetools inspect <ref> --format '{{ json .Provenance }}'`.

**To triage a finding.** Confirm it is real and reachable: find the crate in `sbom-<arch>.json`, and check whether the advisory's affected path is one this service actually calls. Then, in order of preference — upgrade the crate (`cargo update -p <crate>`, which is the only outcome that removes the risk); if no fix exists upstream, accept it as a time-boxed exception below; if it is a false positive, say so in the exception's `statement`.

**To accept an exception.** Add an entry to `.trivyignore.yaml` under `vulnerabilities:`. Every entry needs `id`, `statement` (why this is not exploitable here, and what would change that), and `expired_at` (a date, so the decision lapses rather than outliving whoever made it). `scripts/check-trivyignore.py` enforces all three in CI and rejects unknown keys. An exception is a decision to ship a known risk — it needs the same review as any other change.

## What Runs

`deploy.yml` triggers on **release tags (`v*.*.*`) and manual dispatch only** — not on pushes to `main`, and not on pull requests. A two-architecture build plus scan costs roughly 40 minutes and publishes to GHCR, which is not worth spending on every merge. The consequence is that `deploy.yml` scans each image **once**, at the moment it is built. What covers the image after that is [`scheduled-image-scan.yml`](#the-scheduled-re-scan), which re-scans the released images nightly.

`build-and-push` builds the multi-architecture image variants, pushes them to GHCR under immutable `sha-<short>-<variant>` tags only, records each produced index digest, and attaches SBOM and SLSA provenance metadata. `scan-image` then inspects those images by digest. `promote-tags` applies the semver and `latest` variant tags to the same digests after the scan. `deploy` runs last and deploys **the same promoted digest** that was scanned.

A dispatch run exercises the build, the scan and every assertion without releasing: `promote-tags` and `deploy` both require `github.event_name == 'push'`, so a dispatch promotes nothing and deploys nothing even when aimed at a tag ref. It does still push `sha-<short>-<variant>` images to GHCR — it publishes images, it just never advertises or ships them.

The image is pushed before it can be scanned. That is not a tradeoff, it is a constraint: BuildKit attestations can only be produced when pushing directly to a registry, because the local image store cannot hold an image carrying attestations. What the pipeline controls is not whether the artifact exists in GHCR, but what it is _called_. An image that has not passed the scan is reachable only by its commit SHA tag. It never becomes `latest`, never becomes `v1.2.3`, and never reaches production.

That distinction matters more than it first appears. Blocking only the deploy would still leave `latest` and the semver tags resolving to a rejected artifact, so every consumer that is not this pipeline — anything pulling `latest`, any other chart, any developer running `docker pull` — would receive precisely the image the scan refused. Withholding the tags is what makes the refusal mean anything outside this workflow.

`scan-image` runs one scan and derives every view from it:

| Step                     | Severities     | Unfixed  | Ignore file   | Fails the job          | Output                               |
| ------------------------ | -------------- | -------- | ------------- | ---------------------- | ------------------------------------ |
| Resolve arch manifests   | n/a            | n/a      | n/a           | Yes                    | One scan ref per architecture        |
| Scan image (per arch)    | All            | Included | Not applied   | No                     | `trivy-image-report-<arch>.json`     |
| Derive reports           | All / HIGH+    | Included | Gate set only | No                     | `.txt`, two gate sets per arch       |
| Collect published SBOMs  | n/a            | n/a      | n/a           | After 3 failed fetches | `sbom-amd64.json`, `sbom-arm64.json` |
| Job summary + artifacts  | n/a            | n/a      | n/a           | No (`if: always()`)    | Summary, run artifacts               |
| Assert SBOMs list crates | n/a            | n/a      | n/a           | Yes                    | None                                 |
| Prove the gate can fail  | n/a            | n/a      | n/a           | Yes                    | None                                 |
| Vulnerability gate       | HIGH, CRITICAL | Included | Applied       | Yes                    | Blocking + suppressed counts         |

`Derive reports` produces two HIGH/CRITICAL sets per architecture: `trivy-highcrit-all-<arch>.json` before the exception ledger and `trivy-gate-findings-<arch>.json` after it. The gate reports the difference, so a green result distinguishes "nothing was found" from "everything found was accepted".

Three properties of that ordering are deliberate. The scan runs before the SBOM fetch, because registry metadata is a separate failure domain and a transient `imagetools` error must not cost the reports a responder is being told to go and read. Reports and artifacts publish _before_ any assertion runs, both under `if: always()`, so a failing assertion still leaves the full report to triage — as two artifacts rather than one, so a lost SBOM cannot take the scan results down with it.

And every view is derived from that architecture's single scan by `trivy convert` rather than by re-scanning, so the table a maintainer reads and the set the gate evaluates are provably the same data. The gate renders its table from `trivy-gate-findings-<arch>.json` itself rather than re-applying the same filter to the full report, so the count in the summary, the table in the log, and the exit code cannot disagree about what blocks.

### The Gate Blocks

Any HIGH or CRITICAL finding that survives the exception ledger fails `scan-image`, which withholds the release tags and production.

`ignore-unfixed` is off. That flag exists to mute distro base-image noise, and there is no distro here — the runtime image is `FROM scratch`. The single justification for the flag does not apply, and leaving it on would suppress exactly the class most worth a human decision: a fresh CRITICAL in a crate before upstream ships a fix.

These thresholds do not match the `trivy-config` job in `CI.yml`. That job keeps Trivy's default unfixed handling for Helm misconfigurations; this one deliberately surfaces unfixed crate advisories, for the reason above.

Turning the flag off was safe to do because the surface was measured first rather than assumed, and it was zero — no HIGH or CRITICAL anywhere in the tree at the pinned versions. `rsa` and `rkyv`, the two advisories `deny.toml` ignores, produce nothing under Trivy at these versions, which is why neither needs a `.trivyignore.yaml` entry; see [Two Ledgers](#two-ledgers).

`Cargo.lock` is a sound upper bound on what the image can contain, which is what lets you reason about the image before one exists. The runtime image is `FROM scratch` holding one static binary, a CA bundle and passwd entries, so it has no OS package database — every package a scanner finds comes from the `.dep-v0` section, and that section records only the crates actually linked for the enabled feature set. The containment is strict: lockfile ⊇ linked crates ⊇ the set Trivy evaluates. That also means the build-time `.dep-v0` assertion and the scanner count different things by design; the assertion only proves the section is present and non-empty.

#### Every release proves the gate can still fail

A clean scan is the expected result on every run, and that is the problem: a gate that has never fired is indistinguishable from a gate that cannot fire. Both print nothing and exit zero.

So `scan-image` runs a self-test immediately before the gate, invoking `scripts/vuln-gate.sh` — the same script, flags and `trivy` binary the real gate uses one step later — against two fixtures in `scripts/testdata/`. A fixture holding one CRITICAL **must** fail the gate; a clean one **must** pass, because a gate that blocks unconditionally is equally broken and would otherwise surface mid-release.

Exit status alone is not sufficient evidence. A missing fixture, a `trivy` not on `PATH` and a malformed report all exit non-zero, so checking only the exit code would let a fixture that was never committed read as a _passing_ self-test — the absence-reads-as-success failure the step exists to prevent, occurring inside it. The step therefore also asserts the fixture exists, holds at least one finding, and that the gate's output names the vulnerability ID it was given. Only a gate that really evaluated the report can print that ID back.

The gate is a script rather than an inline step for the same reason. Inline, the self-test and the gate would be two copies of a flag list that must not drift, and the drift would be undetectable: a self-test passing against different flags than the real gate uses tells you nothing about the real gate.

### Where Results Go

Results land in two places, with different lifetimes:

- **The job summary**, for the run you are looking at. Deliberately brief — what was scanned, per-architecture counts, and the gate decision. The full tables are not reproduced there; burying the decision under them is how a summary stops being read.
- **Run artifacts**, in two parts: `container-scan-reports` (the unfiltered JSON, the tables, and both gate sets, per architecture) and `container-sboms`. Both expire with the repository's artifact retention (90 days by default).

**`deploy.yml` itself files no code scanning alerts.** That is a consequence of its trigger, not an oversight: it runs only on `refs/tags/*`, and code scanning files an analysis against a ref, so alerts for a tag are not surfaced in the Security tab's branch view. An upload would succeed into a place nobody reads, which looks like coverage without being any — the failure mode the rest of this pipeline exists to eliminate. Emitting a SARIF nothing consumes would be the same thing one step earlier, so `scan-image` does not produce one at all.

The durable sink is [`scheduled-image-scan.yml`](#the-scheduled-re-scan) instead, which runs on a branch ref and so files alerts where they surface. Release-run results still live only as long as artifact retention; the standing record of what is wrong with the released images is the nightly one.

If you want SARIF from a particular release run, derive it from the artifact — Trivy converts the report that is already kept:

```bash
trivy convert --format sarif --output image-amd64.sarif trivy-image-report-amd64.json
```

Helm and workflow findings are unaffected — `kube-linter` and `zizmor` upload SARIF from `CI.yml`, which does run on branches and pull requests.

### The Scheduled Re-scan

`.github/workflows/scheduled-image-scan.yml` runs nightly and on dispatch. It scans the **released** images rather than building anything: for each variant it resolves `latest-<variant>` to an index digest, resolves each architecture's child manifest under it, and runs the same gate the release path runs. Four scripts are shared with `deploy.yml` — `resolve-arch-manifests.sh`, `derive-trivy-reports.sh`, `vuln-gate.sh` and `gate-selftest.sh` — precisely so the two results are the same measurement rather than two similar ones.

The exception is the ledger itself: the re-scan applies `.trivyignore.yaml` as it stands on the default branch **now**, not as it stood when the image was released. That is the intended direction — current policy, applied to the artifact that is actually running — but it means an exception landed on `develop` for a not-yet-released fix will suppress a finding that is still live in production. When adding an entry, check whether it describes the released image or only the unreleased one.

It exists for three things the release path structurally cannot do:

- **Advisories published after a release reach the gate.** This is the capability discussed under [Relationship to Source-Level Checks](#relationship-to-source-level-checks); a scan tied to releases cannot cover a time axis.
- **`expired_at` gets advance notice.** `scripts/check-trivyignore.py --expiring-within 30` lists exceptions lapsing inside the window, days before they do, off the release path. A _finding_ never fails the run — a date three weeks out is notice, not a fault — but a _checker that could not run_ does, because it presents as "nothing is expiring" and this is the only warning an `expired_at` gets before it lands on a release. Notice is delivered on three surfaces so a green run cannot swallow it: a warning annotation on the run, the job summary, and a comment on the tracking issue when the set of lapsing entries changes.
- **Findings get a durable home.** SARIF is uploaded once under `category: container-image` from a branch ref, so alerts deduplicate, keep history and can be dismissed.

Three structural details are load-bearing.

**The per-variant legs render the gate but do not decide the run.** A single verdict is aggregated afterwards, so the counts, the tracking issue and the exit code cannot disagree about what was found across five variants.

**A leg that dies becomes a row, not a blackout.** The matrix is `fail-fast: false` so one variant's registry trouble cannot withhold the others' findings, and the reporting honours that rather than undoing it: a variant that never reported is recorded with `status: failed`, and the summary, the tracking issue and the SARIF are still published. Information and verdict are separate channels. What stays gated on the aggregation is the **tracking issue** specifically, so that a _total_ infrastructure failure does not file an issue titled as if a vulnerability were found — that is how a tracking issue stops being read. The red run is the infrastructure notification; the issue is the findings record.

Be precise about how far that gate reaches: aggregation fails only when no variant produced a summary at all, or when no variant resolved a released image. A **single** leg dying — one variant's Trivy database fetch failing, say — does not gate it, because the other four still measured something worth recording. That run updates the issue and names the variant under "never reported", which is the intended behaviour: partial coverage is reported as partial, not withheld. The guarantee is "an issue is never filed off a run that measured nothing", not "an issue is never filed when anything went wrong".

**Absence never reads as success — but red is reserved for the promise.** The promise is about the image serving production, so the run fails if the deployed variant (`vars.IMAGE_VARIANT`) was not scanned, if findings survive the ledger, or if the expiry checker could not run. A **non-deployed** variant failing to resolve or never reporting is a warning annotation and a row, not a red run: it is already visible in the summary and the issue, and failing over it buys nothing while costing the signal. That distinction is deliberate. Failing on any unresolved variant meant adding a variant to the matrix produced weeks of consecutive red nightlies — until the next release published its tag — in the same workflow that refuses to fail on an approaching expiry precisely because a cron that is always red stops being read. The deployed variant is checked by name, so keeping the others advisory opens no hole.

The digest resolver still distinguishes "the tag is unreachable" from "the tag is there but we could not read a digest out of it": the first is reported as unscanned, the second is a hard failure, because a resolver that quietly stopped working would otherwise present as a permanently green nightly that scans nothing.

**The variant list is asserted, not trusted.** GitHub does not expose the `env` context to `strategy.matrix`, so the list is restated in `deploy.yml`'s three fan-out matrices and a fourth time in the re-scan. That drift is asymmetric and the dangerous half is invisible: a variant added to `deploy.yml` but not to the re-scan is built, promoted, deployed and **never re-scanned**, with nothing going red. `scripts/check-variant-parity.py` compares all four lists on every pull request and again at the top of the nightly, so it fails for whoever adds the variant rather than for nobody at 03:37.

**`vars.IMAGE_VARIANT` is read from the repository scope, and that is enforced.** `deploy.yml`'s deploy job runs in `environment: production`, where `vars` resolves environment-scoped values first. The nightly declares no environment on purpose — a cron waiting on production's reviewers would never run — so it can only see the repository-scoped value. An environment-scoped override would therefore be invisible to it, and the "the deployed variant was scanned" assertion would silently start verifying a variant nobody runs. `deploy.yml` is the only place both scopes are visible at once, so it compares them and **fails the deploy** if they diverge. Do not remove that check without also changing how the nightly resolves the variant.

The SARIF is converted from `trivy-highcrit-all-<arch>.json` — the pre-ledger HIGH/CRITICAL set `derive-trivy-reports.sh` already wrote — not from the gate set. An accepted exception therefore still files an alert to be dismissed in the UI, so `.trivyignore.yaml` cannot quietly hide a finding from the Security tab. Converting that file rather than re-filtering the full report also keeps the severity floor in exactly one place: a `--severity` flag here would be a second copy of the gate configuration, and changing the floor in the script would leave the alerts silently on the old one.

Each run's location URIs and messages are prefixed with `<variant>/<arch>` before the ten per-variant, per-architecture SARIF documents are merged into one upload. Trivy names every run's tool `Trivy`, sets no `automationDetails` and no `partialFingerprints`, and for a `FROM scratch` image holding one Rust binary the result location is that binary's path — identical across all five variants. Without the prefix, ten runs uploaded under one category would collapse into a single set of alerts and lose the only distinction that matters: which image a finding is actually in.

**One tracking issue, not one per run.** It is located by the `scheduled-image-scan` label, which the run creates with `gh label create --force` first. That ordering is the point: `gh issue create --label` fails outright when the label does not exist, and the notification path must not break on repository configuration — but `--force` is a no-op when it already does, so the objection costs one idempotent line rather than a body search. A label is also an _exact, unbounded_ key, where a search through open issue bodies has to be paged; paged at 100, it silently stops finding the tracking issue once the repository crosses that many open issues and opens a fresh one every night, which is the precise failure "one issue, not one per run" exists to prevent. If more than one open issue ever carries the label the run fails rather than picking one, because silently adopting one and orphaning the rest is the same guarantee breaking where nobody can see it. The body carries the previous advisory ID set **and the previous set of lapsing exceptions**, and is rewritten every run; a **comment** is posted only when one of those two sets changes, and names what was added and removed. A findings set that is stable across nights is therefore silent.

Expiry belongs in that key rather than alongside it. Keyed on advisories alone, the warning was silent in exactly the state this design drives itself into: because the issue is deliberately left open after findings clear, an exception entering the 30-day window on an otherwise-clean night rewrote the body — which notifies nobody — and posted no comment, on a green run. The lapsing set is keyed as `id@date`, not as a day count, so the nightly countdown does not post a comment every morning; it changes only when an entry enters the window or is re-argued.

When findings clear, the issue is updated to say so and **left open** — closing an issue someone is mid-triage on is a worse failure than a stale-looking open one, and reopening loses its place in whatever board or filter it was in.

### The Scanned Artifact Is the Deployed Artifact

The scan binds to `...@sha256:<digest>`. `promote-tags` retags that same digest, and the deploy resolves the promoted variant tag back to its index digest before passing it to the chart via `statuslist.image.digest`, which `helm/chart/templates/deployment.yaml` prefers over `statuslist.image.tag`. Tags stay in place for readability but no longer determine what runs.

This matters because tags are mutable. Binding the scan to a digest and then deploying by tag would leave a window in which a re-run or a manual push could replace the image in between.

Two `concurrency` groups back that up. The workflow-level group is keyed on the ref, so re-runs of the same tag do not overlap. The `deploy` job declares a second one keyed on `deploy-production`, because two tags pushed in quick succession are _different_ refs and the workflow-level group would let both drive `helm upgrade --wait --rollback-on-failure` against the same release at once. What guarantees production runs the scanned artifact is the digest binding; what the second group prevents is two deploys racing for the Helm release lock.

### Which Architectures Are Scanned

Every architecture the release publishes. The pushed digest names a multi-platform _index_, not an image, so `scan-image` resolves each child manifest with `docker buildx imagetools inspect --raw` and scans `repo@<manifest-digest>` per architecture. Scanning the index directly would leave the choice of platform to Trivy's default — one architecture, silently.

Scanning one architecture and inferring the other is not sound, though it looks it. The two images share a lockfile, and the runtime stage is `FROM scratch` with no OS packages, so it is tempting to conclude the package sets must match. They are built by different builder images to different Rust targets, and `cargo auditable` records the graph Cargo _resolved for that target_ — a lockfile is the union across targets, not the per-target set. An advisory reaching only `linux/arm64` would have been promoted and deployed without ever crossing the gate.

The resolution step fails if the index does not contain exactly one manifest per requested architecture, which is a real condition with a real cause: the build stopped producing a platform this pipeline claims to scan.

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
  --features "postgres,aws"

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

The steps are in the [Operator Guide](#operator-guide). Two things that section leaves out:

Read the full report artifact, not just the gate output — the gate applies a severity floor and the exception ledger, and the artifact does not, so a finding can be real and simply below the threshold. And when judging whether an advisory applies, the relevant build is the image's feature set (`postgres,aws`, the `ARG FEATURES` default in the `Dockerfile`), which is narrower than what `cargo build --all-features` compiles.

Do not add an exception for a finding you could simply fix. An exception is for a fix that does not exist yet, cannot be taken yet, or a finding that does not apply — and the `statement` should record which of those three it is.

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

The same widening is reachable by simply **omitting** `paths`, so misconfiguration entries are required to carry a non-empty `paths` or `purls` list. Catching the typo but not the omission would leave the easier route open. Vulnerability entries are exempt from that requirement: a `FROM scratch` image holding one binary has no meaningful path to scope a crate advisory to, so an unscoped entry is the intended form there and demanding `paths: ['**']` would be noise. Where either key _is_ present, in any section, it must be a non-empty list of non-empty strings — `paths: []` is unscoped just as surely as no `paths` at all.

Duplicate IDs are deliberately _not_ rejected: the same rule legitimately appears more than once when it is scoped to different `paths`.

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

The [scheduled re-scan](#the-scheduled-re-scan) is what keeps that from landing on the release path. It lists entries lapsing within 30 days, nightly, so an expiry is notice given days ahead rather than a blocked release discovered by whoever is trying to ship. Without it the first symptom of a lapsed exception is a red release, which is the worst moment to be re-arguing one.

This file is read by two consumers on different cadences — the `trivy-config` job in `CI.yml` on every pull request, and the image scan on releases. A malformed entry added here under incident pressure breaks pull request CI for the whole repository, not just the release path.

## Tool Ownership

`cargo-auditable` and `rust-audit-info` are pinned in the `Dockerfile` as build arguments, and nothing bumps them. Dependabot's `cargo` ecosystem reads `Cargo.toml` and `Cargo.lock`, its `docker` ecosystem reads `FROM` tags, and neither parses `RUN` arguments.

That matters because `rust-toolchain.toml` is `channel = "stable"`, so the toolchain moves on its own and `cargo-auditable` wraps rustc — the coupling breaks without any commit touching it. The symptom is a builder-stage failure in the deploy path, at the `cargo install` layer or the `rust-audit-info` assertion, on a commit that changed nothing relevant. Bump both pins against crates.io when it happens.

This is an accepted gap: a loud build failure is worse than a bump PR but better than a silently empty SBOM, and a scheduled crates.io poller would itself be unmonitored automation. Renovate's regex manager would close it properly.

## Relationship to Source-Level Checks

`cargo-audit`, `cargo-deny`, and `cargo-vet` already query RustSec against the dependency tree on every pull request. The image scan queries the same advisory database, so it will rarely surface a crate advisory that source-level CI did not.

What it adds today is narrower than that overlap suggests:

- The SBOM describes the artifact that ships, not the source tree it was built from, and is published with the image for downstream consumers.
- It detects drift if the image was built from a lockfile that source-level CI never audited.
- It binds a scan result to an image digest, so what was checked and what runs are the same artifact.

The capability that makes image scanning worth having on its own — **catching advisories published _after_ merge, with no source change** — is delivered by the scheduled re-scan rather than by `deploy.yml`. Source-level CI cannot cover a time axis at all: `cargo-audit`, `cargo-deny`, and `cargo-vet` query RustSec on every pull request, which means only when someone is pushing code. `deploy.yml` cannot cover it either, because it triggers only on release tags and manual dispatch, so it scans each image **once** and never again.

[`scheduled-image-scan.yml`](#the-scheduled-re-scan) closes exactly that. It runs nightly against the released images, so an advisory published the day after a release is found that night rather than by blocking whichever release is cut next — which may be weeks later, is not tied to the advisory, and may itself be the urgent fix for something else.

The division of labour is unchanged: the source-level checks cover the dependency tree and usually see a crate advisory first, when CI is running. The nightly covers the artifact when nothing is running.

Findings about crates belong to `cargo-audit` and are fixed at the lockfile. Findings about the image belong here.

### The Release Feature Set

Source-level CI compiles two feature sets: `--all-features`, and `--no-default-features --features memory`. The image is built with neither. Its `ARG FEATURES="postgres,aws"` names a combination that was reachable from no CI job at all.

Nothing validated that string. `ARG FEATURES` is a bare string handed to `cargo build` inside the image build, so a value naming no real feature is caught only when someone cuts a release.

`--all-features` does not stand in for the real set either. Cargo unifies features across the dependency graph, so enabling every feature of this crate compiles its shared dependencies with the union of theirs: `--all-features` turns on `postgres`, `sqlite`, and `mysql` together and builds `sea-orm` with all three `sqlx` backends, where the release set builds it with `sqlx-postgres` alone. The secret backends behave the same way — `--all-features` compiles `vault`, `gcp`, `azure`, and `aws` at once; the image ships `aws` by itself.

This is the shape worth remembering: **enabling every feature is not a superset of shipping some of them.** Unification builds the graph differently, and `#[cfg(not(...))]` branches exist only in the absence of a feature — so `--all-features` is its own configuration, not an upper bound on the ones you ship.

`cargo-build` now runs a `Release image feature set` step that reads `ARG FEATURES` out of the `Dockerfile` and checks that combination, so the release build's feature set is verified on every pull request rather than at release time. Reading it from the `Dockerfile` rather than repeating it is deliberate: a duplicated feature list would drift, and the drift would restore the gap silently.

## Known Gaps

- **Crate advisories are suppressed in two unconnected ledgers**, `deny.toml` and `.trivyignore.yaml`. Nothing keeps them in agreement; see [Two Ledgers](#two-ledgers).
- **The re-scan reads GHCR, not the cluster.** [`scheduled-image-scan.yml`](#the-scheduled-re-scan) scans `latest-<variant>`, which `promote-tags` only ever applies to a digest that passed the release gate — so it names a real released artifact, not an arbitrary one. It is nonetheless an inference about what is running, and there are four ways it can be wrong: an operator ran `helm rollback`; a prerelease was deployed (`latest` is withheld on tags containing `-`); a release promoted tags but failed before `deploy`; or `vars.IMAGE_VARIANT` changed without a redeploy. Reading the digest from the live cluster would settle it, at the price of standing cluster-read credentials in a nightly workflow on a branch ref — a larger security decision than the one it fixes. The run prints the index digest and both per-architecture manifest digests, so the inference can be checked against `kubectl get pod -o jsonpath='{..imageID}'` in seconds; note that a node may report either the index or the per-architecture manifest, so compare against whichever matches. What the workflow _does_ enforce is that the inference was actually evaluated: if `vars.IMAGE_VARIANT` names a variant that was not scanned — or names one the matrix does not build at all — the run fails rather than reporting on the other four.
- **The nightly's reporting logic is only partly tested.** The gate it runs is proven on every run by `scripts/gate-selftest.sh`, the `expired_at` window has unit tests, and the variant lists are asserted by `scripts/check-variant-parity.py` — but the tracking-issue state machine, the aggregation and the SARIF merge are still exercised only by running them. That state machine is the notification path for a security control, and when it misbehaves the symptom is silence, which is indistinguishable from a clean scan. It is also unreachable before merge: `schedule:` and `workflow_dispatch:` only fire from the default branch, so the first live signal arrives on the first night after this lands. Extracting the issue decision into a testable script, the way the gate already is, is tracked in [#469](https://github.com/adorsys/status-list-server/issues/469).
- **A scheduled workflow is disabled after 60 days without repository activity.** GitHub stops running the cron and does not fail anything; the Security tab keeps showing the last upload, and this document keeps claiming nightly coverage. For a workflow whose entire value is covering a time axis, the failure mode is that it silently stops covering it. Re-enable it from the Actions tab. Nothing here detects the condition, because the thing that would detect it is the workflow that is not running.
- **Release-run scan results still never reach GitHub code scanning.** Alerts filed against a `refs/tags/*` ref are not surfaced in the Security tab's branch view, so `scan-image` deliberately emits no SARIF; the nightly is what files alerts, from a branch ref. See [Where Results Go](#where-results-go).
- **BuildKit attestations are unsigned** and carry no Sigstore identity, so provenance has no verifiable issuer. It is a record of the build, not evidence about it: anyone with push access to the repository could produce an equivalent document. Adding `actions/attest-build-provenance` is tracked in [#402](https://github.com/adorsys/status-list-server/issues/402), and is not a one-line change — it emits a second provenance document alongside BuildKit's, which forces a decision about keeping both or setting `provenance: false` and giving up the `mode=max` build detail.
- **Gate behaviour is reproducible against a fixed advisory database, not across time.** A finding can move from absent to blocking with no change in this repository. That is intentional — it is how post-merge advisories are meant to reach the gate — but it means "reproducible" holds for a given database snapshot.
- **The Trivy vulnerability database is fetched unauthenticated from a third party.** `trivy-action` caches it across runs by default (`cache: true`, an `actions/cache` entry keyed by date), so this is not a fresh download per scan — but the cache is stale by construction on a nightly that runs once every 24 hours, so in practice each night's five jobs each re-fetch it. On the release path a network blip or a GHCR rate limit becomes a failed release, surfacing as the security gate failing, which reads as "a vulnerability was found". Tracked in [#405](https://github.com/adorsys/status-list-server/issues/405); a mirrored or authenticated `TRIVY_DB_REPOSITORY` is the actual fix, and enabling caching is not it because caching is already on. The nightly is defended against the _confusion_ rather than the fault, though only at the extreme: if the database failure takes out every variant, nothing aggregates, the run goes red and no issue is filed. A failure hitting one variant leaves the other four measuring, so the issue is still updated — with that variant listed as never reported, which is what partial coverage should look like.
- **The builder-stage audit assertion runs only on the release path.** `deploy.yml` does not run on pull requests, so a change that breaks the auditable build is green on the PR and fails during a release. Tracked against [#316](https://github.com/adorsys/status-list-server/issues/316).
- **An expired ignore entry is a warning, not a failure.** `scripts/check-trivyignore.py` enforces the required fields but only warns when a date has passed, because an expired entry has already stopped suppressing anything. The nightly now gives 30 days' notice before that happens, so the remaining question — whether a _lapsed_ entry should fail pull request CI — is a policy decision that has deliberately not been made here.
- **There is no break-glass for the gate.** With `ignore-unfixed` off and any HIGH or CRITICAL blocking, a newly published unfixed advisory in a linked crate makes it impossible to cut _any_ release, including a security hotfix for something unrelated. The only path is landing a `.trivyignore.yaml` entry through pull request CI — which is the file this document warns hardest against editing under incident pressure. `workflow_dispatch` deliberately cannot release, so it is not an override. A dispatch input gated on the `production` environment's reviewers, recording the justification in the run summary, would close this; it is a policy decision rather than a mechanical one and has not been made.
