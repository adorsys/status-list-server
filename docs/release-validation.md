# Release validation checklist

Use this checklist for the first end-to-end promotion exercise tracked in
[#735](https://github.com/adorsys/status-list-server/issues/735). The branch
flow, version rules, and hotfix procedure are in [Contributing](../CONTRIBUTING.md#release-and-versioning).
The [deployment runbook](deployment-runbook.md#existing-eks-release-with-file-backed-signing)
covers the EKS prerequisites, verification, and migration-aware rollback.
Record links and non-secret identifiers in the issue or release record. Do not
record credentials, certificate private keys, tokens, or Secret contents.

The RC and final tag both deploy to the existing `statuslist` EKS release. This
is not an isolated test environment. Its file-backed signing profile uses one
replica and a `Recreate` rollout, so each deployment briefly interrupts service.
Schedule the exercise with the release owners and integrators. Use the next
intended release for the live exercise: a final tag and the RC it promotes are
release records, not temporary test tags to delete afterward.

## Before a live promotion

- [ ] Confirm the `gate` workflow and `scripts/promotion-gate.sh` are on both
  `stage` and `main`. Require the `gate` check on both targets, and require
  up-to-date branches on `main` only; verify the check actually runs before
  making it required.
- [ ] Confirm `stage`, `main`, and `hotfix/*` protections enforce the branch
  flow and review rules in [Contributing](../CONTRIBUTING.md#release-and-versioning).
  Confirm `v*` tag creation is restricted to the release-bot App.
- [ ] Confirm release-owner approval is required by the `release` environment
  before the final tag is created, and deployment approval is required by the
  `production` environment for RC and final tags.
- [ ] Complete the EKS and database checks in the
  [file-backed signing runbook](deployment-runbook.md#existing-eks-release-with-file-backed-signing):
  namespace access, issuer-registry ConfigMap, `IMAGE_VARIANT=fscert`, ESO and
  cert-manager readiness, existing-release ownership, database backup, and
  credential inventory. Do not trigger a tag while a prerequisite is unresolved.
- [ ] Confirm the latest final tag is in `develop` history and no release-plz PR
  for another target branch is open. Prepare a new version with **Release-plz PR**
  on `develop`; review and merge it before promoting. The version must be newer
  than the latest final tag or the RC workflow refuses to create a candidate.
- [ ] Confirm `stage` will contain the current `main` history before cutting
  the RC; the `stage` → `main` gate rejects a candidate that omits it.
- [ ] Agree on the deployment window, validation owner, rollback decision
  maker, and the checks that will count as a successful EKS rollout. Review
  [rollback across migrations](deployment-runbook.md#rolling-back-across-migrations)
  before the window.

## Normal promotion: `develop` → `stage` → `main`

1. Merge a reviewed `develop` → `stage` PR with a merge commit. Check its
   `gate` and required CI results. Record the `stage` commit.
2. Wait for **Tag Release Candidate** to create `v<version>-rc.<N>` from that
   commit. Record the tag, commit, and workflow run. A failed or incomplete
   **Build and Deploy to EKS** run is not a validated candidate.
3. In the candidate's **Build and Deploy to EKS** run, verify CI, Helm checks,
   image scan, provenance verification, direct upgrade from the last final
   release, and **Deploy to Production** all pass. Record the run URL and the
   `image-digest-fscert` artifact's index digest. Confirm the Helm release and
   pod are ready, the deployed image is pinned to that digest, and the expected
   issuer and status-list smoke checks pass. Use the runbook's
   [verification commands](deployment-runbook.md#verification).
4. If `stage` changes after that candidate, cut and validate a new RC. The
   highest-numbered RC must be the one promoted; an older successful RC cannot
   stand in for a newer failed one. Avoid editing release files between RC
   validation and final promotion: the final commit must have the candidate's
   file tree.
5. Merge a reviewed `stage` → `main` PR with a merge commit after `gate`
   confirms that its head is the latest validated RC. Record the PR and merge
   commit. Wait for release-owner approval and for **Release-plz release** to
   create `v<version>`.
6. In the final tag's **Build and Deploy to EKS** run, confirm **Resolve Image
   Source** names the validated RC and run, the **Build and Push Docker Image to
   GHCR** jobs are skipped, the image is rescanned, and tag promotion and
   deployment succeed. Compare the final `fscert` tag, deployed image, and RC
   digest artifact: all must resolve to the same index digest. Confirm
   provenance names the RC ref, not the final ref. Record the final run,
   digest, Helm revision, and smoke-check result.

If a gate, scan, direct upgrade, migration, readiness check, or digest comparison
fails, stop promotion and investigate that failure. A later candidate is needed
after any change to `stage`. Follow the runbook before rolling back a release
that may have applied a migration.

## Hotfix path

Validate the path without creating a second live release unless a real hotfix
is needed. Run the existing promotion-gate, release-candidate, and deployment
workflow tests, and record their CI run. In a disposable Git repository or
other isolated test, verify these cases and retain the commands and outcomes:

- [ ] A `hotfix/*` branch starts at the released `main` commit; Release-plz
  prepares a newer patch version and changelog on that branch.
- [ ] A candidate made from the hotfix head passes the same validation before
  `hotfix/*` → `main` can pass `gate`.
- [ ] The gate rejects an older version, an unvalidated candidate, a branch
  missing current `main`, and a head that differs from the latest RC.
- [ ] The final path selects the hotfix RC digest without rebuilding it. A
  merge-commit back-merge of `main` into `develop` retains the final tag in
  `develop` history; any version conflict keeps the development version and
  adds the hotfix changelog section.

If a real hotfix is released, record its RC, final digest, EKS checks, and
back-merge using the normal-promotion evidence fields below.

## Evidence and cleanup

Add a short record to #735 or a linked release record. Leave fields blank until
the corresponding validation has actually run.

| Evidence | Link or value |
| --- | --- |
| Release window and approvers | |
| Preflight results and database backup reference | |
| Release-plz PR and prepared version | |
| `develop` → `stage` PR, gate run, and stage commit | |
| RC tag, commit, and tagging run | |
| RC deploy run and direct-upgrade result | |
| RC `fscert` index digest and deployed Helm revision | |
| RC readiness and smoke-check results | |
| `stage` → `main` PR, gate run, and merge commit | |
| Release approval, final tag, and final deploy run | |
| Final tag and deployed digest comparison with the RC | |
| Final readiness and smoke-check results | |
| Hotfix validation commands, test run, and outcomes | |
| Cleanup performed and remaining follow-ups | |

Remove only scratch branches, disposable test repositories, and any temporary
deployments made for the isolated hotfix validation. Keep the promoted RC tag,
final tag, GitHub release, recorded digests, and run links as release evidence.
The workflow artifacts remain available only for the repository's retention period.
If the first file-backed rollout used list-quota transition mode, run the
[recount and enable steps](troubleshooting.md#upgrading-to-the-list-quota)
afterward and track removal of the transition flag in [#776](https://github.com/adorsys/status-list-server/issues/776).
