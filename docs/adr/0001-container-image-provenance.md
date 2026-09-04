# 1. Keep both container image provenance documents

- **Status:** Accepted
- **Date:** 2026-09-02
- **Issue:** [#402](https://github.com/adorsys/status-list-server/issues/402)

> This is the first ADR in this repository and establishes the convention: Nygard's four sections — Status, Context, Decision, Consequences — numbered sequentially from `0001`, one decision per file. Sub-headings within those four are allowed where a decision has genuinely separable parts; inventing a different top-level shape is not.
>
> The body is not rewritten after acceptance. `Status` may change (superseded records point at the ADR that replaced them), and a factual correction is recorded as a dated **Amendment** at the end rather than by editing the text it corrects — a reader who acted on the original needs to see what it said and why it was wrong, which an edit destroys. This ADR has one; see [Amendments](#amendments).

## Context

`deploy.yml` builds with `provenance: mode=max`, so BuildKit attaches a SLSA Provenance **v0.2** attestation (`https://slsa.dev/provenance/v0.2`) as an in-toto manifest inside the pushed OCI index.

That attestation is **integrity-protected**. The index digest chain covers it, so it cannot be altered without changing the image digest, and `promote-tags` already fails a release if it disappears.

It is **not authenticity-protected**. The `builder.id` field pointing at the Actions run is self-asserted: it is JSON BuildKit wrote, with nothing binding it to the run that allegedly produced it. Anyone with push access to the GHCR package can push an index carrying a fabricated provenance manifest that inspects identically under `docker buildx imagetools inspect`.

**The gap is "who said this," not "was this changed."** The two are easy to conflate and the distinction is the whole decision.

This matters here more than it would in most repositories. This service is an authority other systems trust. A compromise of package push access currently escalates to a compromise of everything downstream that pulls the image, because no consumer can distinguish an image we built from one someone else pushed with a matching provenance claim.

The non-obvious part, and the reason this was never a one-line change: **`actions/attest-build-provenance` does not sign the BuildKit attestation.** It generates a second, independent provenance document over the same image digest — SLSA Provenance **v1** (`https://slsa.dev/provenance/v1`), signed via Sigstore/Fulcio, verified with `gh attestation verify` rather than `docker buildx imagetools inspect`. Different predicate version, different content, different trust properties, different tool. Both end up attached to one image and nothing reconciles them. Enabling it therefore forces a choice about what to do with BuildKit's.

## Decision

**Keep both.** `provenance: mode=max` stays, and `actions/attest-build-provenance` is added alongside it.

Before the reasoning, one mechanical fact, because it changes what was being chosen between: **Option 2 was not available as a one-line change either.** `promote-tags` already asserts that BuildKit's SBOM *and provenance* are present for every published platform, and fails the release if either is missing. Setting `provenance: false` would therefore have failed every release at that step until the assertion was deleted too. So the choice was never "flip a flag or carry two documents" — it was "carry two documents, or remove an existing release-blocking check." A later reader evaluating Option 2 should hit that before they weigh anything else.

With that said, the argument that settles the rest is not that the two documents answer different questions — that is true but soft, and someone will reasonably trade one question away to avoid carrying two documents. The decisive argument is an asymmetry in what a repository-visibility change does to each:

> The explicit `provenance: mode=max` pin exists because `docker/build-push-action` defaults to `mode=max` on public repositories and `mode=min` on private ones, so flipping this repository private would **silently degrade** provenance. GitHub artifact attestations are available in public repositories on all plans, but on private and internal repositories they require GitHub Enterprise Cloud. So under "GitHub's provenance only," that same visibility flip does not degrade provenance — it **removes** it. Option 2 is strictly worse against the exact threat that motivated the pin it would undo.

Two further points support keeping `mode=max`, neither of them load-bearing on its own. `docs/supply-chain.md` §"Never Pass Secrets as Build Arguments" is written entirely on the premise that `mode=max` publishes every build-arg value; removing it would invalidate a documented security rule as a side effect. And the two predicates are not redundant in content: v0.2 at `mode=max` carries the build *detail* (the LLB definition, the Dockerfile, the build arguments), while the signed v1 statement carries the *issuer identity*. Neither is a superset of the other.

### Sub-decisions

**`push-to-registry: false`, initially.** GHCR's support for the OCI Referrers API is unsettled — reports range from unsupported to recently working. An attestation pushed where nothing can discover it is coverage-shaped and coverage-free, which is the failure this pipeline exists to eliminate. `gh attestation verify` reads GitHub's attestation API by default, so `false` costs nothing today. `docs/supply-chain.md` records what would have to be true to flip it and how to check, so that `false` stays a decision rather than becoming permanent by default.

**`create-storage-record: false`, rather than granting `artifact-metadata: write`.** `actions/attest` needs `artifact-metadata: write` to write the storage record, which captures which registry the image is hosted on and whether it is active. That is genuinely useful, and it is also a third write scope on the job that pushes the production image, for metadata that is not on the verification path being documented — `gh attestation verify` does not read it. Storage records are only produced when pushing to a registry, which this does not do, so setting it explicitly costs nothing and makes a later flip of `push-to-registry` a deliberate two-line change that surfaces the permission question, rather than one that silently starts requiring a scope the job was granted preemptively.

**Rekor / the public transparency log: accepted.** Sigstore records the signing event in Rekor, a public append-only log. Disclosure is a non-issue: the repository is public, the image is public, and `mode=max` already publishes the Dockerfile and every build argument to anyone who can pull. **The consequence actually being accepted is permanence, not confidentiality** — every attested build becomes a permanent public record that cannot be withdrawn. Note specifically that `build-and-push` is not tag-gated: it runs on `workflow_dispatch` as well as on release tags, so a dozen dispatch runs while debugging something produce a dozen permanent public log entries. That is accepted; it is recorded here because it will surprise someone otherwise.

### Permissions

`build-and-push` gains `id-token: write` (to mint the OIDC token Fulcio exchanges for a signing certificate) and `attestations: write` (to persist the signed bundle), scoped to that job.

**These are first-time grants, not a restoration.** `build-and-push` carried exactly `contents: read` + `packages: write` before this change. The `id-token: write` that predates it is on the `deploy` job, where it authenticates to AWS via OIDC, and is unrelated.

**`id-token: write` has a blast radius, and it is a precondition of this decision rather than a footnote to it.** The grant lets *any* step in `build-and-push` mint an OIDC token asserting this repository's identity, and that job builds from the source tree. What the token is worth is whatever trusts that identity, which here is the IAM role `deploy` assumes. **The trust policy for `AWS_DEPLOY_ROLE_ARN` must condition `sub` on `repo:<owner>/<repo>:environment:production`.** Under the looser `repo:<owner>/<repo>:*` form, this grant would let the build job assume the production deploy role — precisely the privilege that putting `deploy` behind `environment: production` exists to gate, handed back by a permission added for an unrelated reason. Verify it before merging a change that adds `id-token: write` to any job; `docs/deployment-runbook.md` carries the check.

## Consequences

**The image gains a verifiable issuer.** A consumer can establish that a specific digest was built by **`.github/workflows/deploy.yml` in this repository**, which no amount of inspecting BuildKit's attestation could establish. Push access to the GHCR package alone is no longer sufficient to publish an image that presents as ours.

That the claim is *specific* rather than repository-scoped is load-bearing, and getting it specific enough took three attempts; see [Amendments](#amendments) for what the first two got wrong and why. As enforced today, `scripts/verify-attestation.sh` pins the certificate's SubjectAlternativeName **exactly** — workflow path *and* ref — with `--cert-identity`, plus `--source-ref` as an independent extension check and `--deny-self-hosted-runners`. `--repo` scopes attestation *lookup* only, so on its own it establishes merely that some workflow here signed the digest; and `--signer-workflow`, the flag that looks like the answer, matches the SAN by *prefix* with the `@<ref>` suffix unconstrained. Since `build-and-push` runs on `workflow_dispatch`, an unpinned ref means repository write access is enough to obtain a genuinely signed attestation over an arbitrary image. **Do not loosen the identity to `--repo`, and do not substitute `--signer-workflow` for it**; `scripts/attestation-selftest.sh` asserts the exact form is passed, asserts the no-ref fallback regex is anchored at both ends, and asserts `--signer-workflow` is *not* passed alongside it — gh resolves `SANRegex`/`SAN` before `SignerWorkflow` and returns early, so passing both would silently ignore the latter.

**Two provenance documents now describe one image, and consumers must be told which to use for what.** This is the cost of the decision, and it is paid in documentation: `docs/supply-chain.md` states which attestation answers which question, and what a consumer should *do* when they disagree.

**The verification command is itself a hazard, and is treated as one.** `gh attestation verify` exited 0 when it found no attestation until gh 2.67.0 ([cli/cli#10418](https://github.com/cli/cli/issues/10418), fixed by [#10421](https://github.com/cli/cli/pull/10421)) — the absence-reads-as-success failure this repository is organised against, occurring inside the command documented as the defence against it. `scripts/verify-attestation.sh` therefore enforces the version floor rather than assuming it, and asserts the *result* on top of it, because exit status alone cannot distinguish a verification from a no-op.

That result is read from `--format json`, not from `gh`'s output text. The obvious text assertion — "the output names the digest we asked about" — does not work: `gh` prints `Loaded digest <digest> for <artifact>` before it fetches anything, echoing back the digest it was handed, so the check is satisfied on every invocation including a #10418-shaped one. An empty JSON result array cannot be produced by a verification that succeeded, and the subject digest in it is the artifact `gh` actually resolved. If that document cannot be read at the documented path, the check fails closed and says the schema moved.

`scripts/attestation-selftest.sh` proves both directions against a stubbed `gh` whose output reproduces the real thing — `Loaded digest` line included, so a regression to a text assertion is rejected there rather than in a release — for the same reason `scripts/gate-selftest.sh` exists: a check that has never rejected anything is indistinguishable from one that cannot.

**Verification is enforced on the release path, before publication, and again at the point of use.** Three places, and the placement is the decision:

- `verify-provenance` verifies the built digest and gates `promote-tags`, so a digest whose provenance does not verify never receives a release tag. Verifying only after promotion would mean `latest-<variant>` is public and pullable before anything has asked who built it.
- `promote-tags` resolves the release tag and verifies what it resolves to, then separately asserts that is the built and scanned digest.
- `deploy` verifies the digest *it* resolved, which is the one that reaches the cluster. `promote-tags` read the tag earlier; a tag is mutable, and verifying anything other than the value about to be deployed verifies an artifact production is not going to run.

`verify-provenance` is deliberately not gated on `push`, so it runs on `workflow_dispatch` too. A stub cannot show that a flag combination is one `gh` accepts, that the token carries the right scope, or that the certificate identity is the one we predicted; without a non-release path exercising the real command, the first execution of it would be during a release, on the last step before a deploy.

**A future move to a private repository breaks the signed attestation unless the organisation is on GitHub Enterprise Cloud.** This is the mirror image of the argument for the decision and must be checked before any such change. BuildKit's `mode=max` provenance would survive it — degraded to `mode=min` unless the explicit pin is kept, which is why the pin stays.

**Not addressed here:** Cosign keyless signing of the image itself, which is a different claim from attestation provenance, and any admission-control or policy enforcement on verification, which is a consumer-side decision. Both are out of scope by choice, not oversight.

## Amendments

### 2026-09-03 — the identity pin and the result assertion were both weaker than this ADR claimed

Review found that two of the load-bearing claims above were true of the *intent* and false of the *implementation*. Both were verified against `cli/cli` source rather than argued from the flag names, and both are recorded here rather than quietly edited into the text above, because the original wording is what a reader would have acted on.

**1. `--signer-workflow` does not pin an identity; it pins a prefix.** This ADR said the workflow-specific claim was load-bearing and that `--signer-workflow` secured it. `gh` turns that flag into `"^" + regexp.QuoteMeta("https://<host>/<owner>/<repo>/<path>")` (`pkg/cmd/attestation/verify/policy.go`, `validateSignerWorkflow`) — anchored at the start only. So the `@<ref>` suffix of the certificate SAN is unconstrained, and since `build-and-push` runs on `workflow_dispatch`, anyone with repository write access could dispatch this workflow from a branch carrying a modified Dockerfile and receive a genuinely signed attestation that verified. The prefix also admits sibling paths such as `.github/workflows/deploy.yml-staging.yml`.

The threat this ADR names is push access. `--signer-workflow` narrowed it from "any workflow in this repository" to "any ref of this workflow" — and dispatching a workflow that already exists is *easier* than adding one, so it closed the wrong half. Corrected to `--cert-identity` (exact SAN, ref included) where the ref is known, an end-anchored `--cert-identity-regex` where it is not, plus `--source-ref` and `--deny-self-hosted-runners`.

**2. "Assert the output names the digest" asserted nothing.** This ADR justified that assertion as the guard against #10418 recurring. `gh` prints `Loaded digest <digest> for <artifact>` to stdout *before* attestation lookup (`pkg/cmd/attestation/verify/verify.go`), echoing back the digest it was given, so the substring was present on every run — including a #10418 replay, where the command reports an image carrying no provenance at all as verified. The self-test appeared to prove the guard only because its stub omitted that line.

Corrected to an assertion over `--format json`. The stub's fixtures are now faithful reproductions of real `gh` output, so a verifier that regressed to a text assertion fails the self-test.

**What the correction did not change:** the decision to keep both provenance documents, the visibility asymmetry that settles it, and both sub-decisions (`push-to-registry: false`, `create-storage-record: false`) all stand as written. The defect was in how the identity was checked, not in what was decided.

**The general lesson, since it is the second time this shape has appeared in this pipeline:** a flag whose *name* describes the property you want is not evidence that it enforces the property you want. Both defects survived review because the flag names read correctly. Verify against the tool's source or against a fixture captured from the real tool — a stub written from the same assumption as the code will agree with it.
