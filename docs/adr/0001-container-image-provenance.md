# 1. Keep both container image provenance documents

- **Status:** Accepted
- **Date:** 2026-09-02
- **Issue:** [#402](https://github.com/adorsys/status-list-server/issues/402)

> This is the first ADR in this repository and establishes the convention: Nygard-minimal — Status, Context, Decision, Consequences — numbered sequentially from `0001`, one decision per file, never edited after acceptance except to change `Status` (superseded records point at the ADR that replaced them). Subsequent ADRs follow this shape rather than inventing their own.

## Context

`deploy.yml` builds with `provenance: mode=max`, so BuildKit attaches a SLSA Provenance **v0.2** attestation (`https://slsa.dev/provenance/v0.2`) as an in-toto manifest inside the pushed OCI index.

That attestation is **integrity-protected**. The index digest chain covers it, so it cannot be altered without changing the image digest, and `promote-tags` already fails a release if it disappears.

It is **not authenticity-protected**. The `builder.id` field pointing at the Actions run is self-asserted: it is JSON BuildKit wrote, with nothing binding it to the run that allegedly produced it. Anyone with push access to the GHCR package can push an index carrying a fabricated provenance manifest that inspects identically under `docker buildx imagetools inspect`.

**The gap is "who said this," not "was this changed."** The two are easy to conflate and the distinction is the whole decision.

This matters here more than it would in most repositories. This service is an authority other systems trust. A compromise of package push access currently escalates to a compromise of everything downstream that pulls the image, because no consumer can distinguish an image we built from one someone else pushed with a matching provenance claim.

The non-obvious part, and the reason this was never a one-line change: **`actions/attest-build-provenance` does not sign the BuildKit attestation.** It generates a second, independent provenance document over the same image digest — SLSA Provenance **v1** (`https://slsa.dev/provenance/v1`), signed via Sigstore/Fulcio, verified with `gh attestation verify` rather than `docker buildx imagetools inspect`. Different predicate version, different content, different trust properties, different tool. Both end up attached to one image and nothing reconciles them. Enabling it therefore forces a choice about what to do with BuildKit's.

## Decision

**Keep both.** `provenance: mode=max` stays, and `actions/attest-build-provenance` is added alongside it.

The argument that settles this is not that the two documents answer different questions — that is true but soft, and someone will reasonably trade one question away to avoid carrying two documents. The decisive argument is an asymmetry in what a repository-visibility change does to each:

> The explicit `provenance: mode=max` pin exists because `docker/build-push-action` defaults to `mode=max` on public repositories and `mode=min` on private ones, so flipping this repository private would **silently degrade** provenance. GitHub artifact attestations are available in public repositories on all plans, but on private and internal repositories they require GitHub Enterprise Cloud. So under "GitHub's provenance only," that same visibility flip does not degrade provenance — it **removes** it. Option 2 is strictly worse against the exact threat that motivated the pin it would undo.

Two further points support keeping `mode=max`, neither of them load-bearing on its own. `docs/supply-chain.md` §"Never Pass Secrets as Build Arguments" is written entirely on the premise that `mode=max` publishes every build-arg value; removing it would invalidate a documented security rule as a side effect. And the two predicates are not redundant in content: v0.2 at `mode=max` carries the build *detail* (the LLB definition, the Dockerfile, the build arguments), while the signed v1 statement carries the *issuer identity*. Neither is a superset of the other.

### Sub-decisions

**`push-to-registry: false`, initially.** GHCR's support for the OCI Referrers API is unsettled — reports range from unsupported to recently working. An attestation pushed where nothing can discover it is coverage-shaped and coverage-free, which is the failure this pipeline exists to eliminate. `gh attestation verify` reads GitHub's attestation API by default, so `false` costs nothing today. `docs/supply-chain.md` records what would have to be true to flip it and how to check, so that `false` stays a decision rather than becoming permanent by default.

**`create-storage-record: false`, rather than granting `artifact-metadata: write`.** `actions/attest` needs `artifact-metadata: write` to write the storage record, which captures which registry the image is hosted on and whether it is active. That is genuinely useful, and it is also a third write scope on the job that pushes the production image, for metadata that is not on the verification path being documented — `gh attestation verify` does not read it. Storage records are only produced when pushing to a registry, which this does not do, so setting it explicitly costs nothing and makes a later flip of `push-to-registry` a deliberate two-line change that surfaces the permission question, rather than one that silently starts requiring a scope the job was granted preemptively.

**Rekor / the public transparency log: accepted.** Sigstore records the signing event in Rekor, a public append-only log. Disclosure is a non-issue: the repository is public, the image is public, and `mode=max` already publishes the Dockerfile and every build argument to anyone who can pull. **The consequence actually being accepted is permanence, not confidentiality** — every attested build becomes a permanent public record that cannot be withdrawn. Note specifically that `build-and-push` is not tag-gated: it runs on `workflow_dispatch` as well as on release tags, so a dozen dispatch runs while debugging something produce a dozen permanent public log entries. That is accepted; it is recorded here because it will surprise someone otherwise.

### Permissions

`build-and-push` gains `id-token: write` (to mint the OIDC token Fulcio exchanges for a signing certificate) and `attestations: write` (to persist the signed bundle), scoped to that job.

**These are first-time grants, not a restoration.** The issue that prompted this work stated that the supply-chain PR had removed `id-token: write` and `attestations: write` from the build job and that the delta should be recorded so the two diffs did not read as contradictory. That is not what happened: `git log -S 'attestations: write' --all` returns nothing, so the string has never existed anywhere in this repository's history, and `build-and-push` carried exactly `contents: read` + `packages: write` immediately before the supply-chain PR and immediately after it. The `id-token: write` that predates this change is on the `deploy` job, where it authenticates to AWS via OIDC, and is unrelated. The claim was asserted from memory rather than from a diff. It is corrected here rather than repeated, because a note whose purpose is to save a future reader time would otherwise send them looking for a removal that never occurred.

## Consequences

**The image gains a verifiable issuer.** A consumer can establish that a specific digest was built by a workflow in this repository, which no amount of inspecting BuildKit's attestation could establish. Push access to the GHCR package alone is no longer sufficient to publish an image that presents as ours.

**Two provenance documents now describe one image, and consumers must be told which to use for what.** This is the cost of the decision, and it is paid in documentation: `docs/supply-chain.md` states which attestation answers which question, and what a consumer should *do* when they disagree.

**The verification command is itself a hazard, and is treated as one.** `gh attestation verify` exited 0 when it found no attestation until gh 2.67.0 ([cli/cli#10418](https://github.com/cli/cli/issues/10418), fixed by [#10421](https://github.com/cli/cli/pull/10421)) — the absence-reads-as-success failure this repository is organised against, occurring inside the command documented as the defence against it. `scripts/verify-attestation.sh` therefore enforces the version floor rather than assuming it, and asserts the output names the digest it was given, because exit status alone cannot distinguish a verification from a no-op. `scripts/attestation-selftest.sh` proves both directions against a stubbed `gh`, including a replay of the 2.66.1 behaviour, for the same reason `scripts/gate-selftest.sh` exists: a check that has never rejected anything is indistinguishable from one that cannot.

**Verification is enforced on the release path, not merely documented.** `promote-tags` already asserts BuildKit's SBOM and provenance survived promotion; it now asserts the signed attestation verifies against the promoted digest too. Omitting that would have left an asymmetry a reader would reasonably read as an oversight, and would have shipped a documented command the pipeline never exercises.

**A future move to a private repository breaks the signed attestation unless the organisation is on GitHub Enterprise Cloud.** This is the mirror image of the argument for the decision and must be checked before any such change. BuildKit's `mode=max` provenance would survive it — degraded to `mode=min` unless the explicit pin is kept, which is why the pin stays.

**Not addressed here:** Cosign keyless signing of the image itself, which is a different claim from attestation provenance, and any admission-control or policy enforcement on verification, which is a consumer-side decision. Both are out of scope by choice, not oversight.
