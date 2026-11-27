# Release validation checklist

Use this checklist for each promotion from `develop` through `stage` to `main`,
and to validate the hotfix path. The branch flow, merge methods, version
rules, and hotfix procedure are in [Contributing](../CONTRIBUTING.md#release-and-versioning).
The [deployment runbook](deployment-runbook.md#existing-eks-release-with-file-backed-signing)
covers the EKS prerequisites, verification, and migration-aware rollback.
Record links and non-secret identifiers in the release's tracking issue or
release record. Do not record credentials, certificate private keys, tokens,
Secret contents, pod logs, SecretStore manifests, or credential-inventory query
results; a database backup is recorded by reference only.

The RC and final tag both deploy to the existing `statuslist` EKS release. This
is not an isolated test environment. Its file-backed signing profile uses one
replica and a `Recreate` rollout, so each deployment briefly interrupts service.
Schedule the window with the release owners and integrators, and allow for
more than one candidate: each RC run takes about 40 minutes before it deploys.
Validate with an intended release rather than a throwaway change. A final tag
creates a GitHub Release, moves the `<major>.<minor>` and `latest` image tags,
and advances the version, none of which can be cleanly undone.

## Before a live promotion

- [ ] Confirm the `gate` workflow and `scripts/promotion-gate.sh` are on both
  `stage` and `main`, and that `gate` is required on both, with up-to-date
  branches required on `main` only. If either branch lacks the files, follow
  [Bringing the gate onto a branch](#bringing-the-gate-onto-a-branch) for that
  promotion instead.
- [ ] Confirm `stage`, `main`, and `hotfix/*` protections enforce the branch
  flow, merge methods, and review rules in [Contributing](../CONTRIBUTING.md#release-and-versioning).
  Confirm only the release-bot App can create, move, or delete `v*` tags.
- [ ] Confirm the `production` environment requires deployment approval for RC
  and final tags. Record the protection rules on the `release` environment,
  which the **Release-plz release** job runs in before it creates the final tag.
- [ ] Record the repository's artifact retention period. The final release
  reads the RC run's `image-digest-*` artifacts, so it must be promoted before
  they expire.
- [ ] Complete the EKS and database checks in the
  [file-backed signing runbook](deployment-runbook.md#existing-eks-release-with-file-backed-signing):
  namespace access, issuer-registry ConfigMap, `IMAGE_VARIANT=fscert`, ESO and
  cert-manager readiness, existing-release ownership, database backup, and
  credential inventory. Do not trigger a tag while a prerequisite is unresolved.
- [ ] Confirm the latest final tag is in `develop` history and no release-plz PR
  for another target branch is open. Prepare a new version with **Release-plz PR**
  on `develop`; review and merge it before promoting. The version must be newer
  than the latest final tag or the RC workflow refuses to create a candidate.
- [ ] Check the Datev-installed chart version and `fscert` image reference with
  its deployment operator. Record the confirmation date and non-secret evidence
  in [issue #780](https://github.com/adorsys/status-list-server/issues/780),
  and ensure `DATEV_BASELINE_TAG` names that installed final release. The issue
  assignee updates the repository variable after each Datev rollout; a missing
  or invalid tag fails the Datev upgrade job and blocks RC promotion.
- [ ] Confirm `stage` will contain the current `main` history before the RC is
  tagged; the `stage` to `main` gate rejects a candidate that omits it.
- [ ] Agree on the deployment window, validation owner, rollback decision
  maker, and a list ID that exists before the upgrade, for the status-list smoke
  check. Review
  [rollback across migrations](deployment-runbook.md#rolling-back-across-migrations)
  before the window.

### Bringing the gate onto a branch

`gate` runs from the base branch's copy of the workflow, so a promotion into a
branch that lacks the gate files runs without it. That promotion is what brings
the files onto the branch. For each such pull request:

1. Before merging, run the gate script from an up-to-date clone of `develop`
   with tags fetched (`git fetch origin --tags`) and an authenticated `gh`.
   Attach its output to the pull request:

   ```bash
   bash scripts/promotion-gate.sh <base> <head-branch> \
     "$(git rev-parse origin/<head-branch>)" \
     adorsys/status-list-server adorsys/status-list-server .
   ```

   Run it again after any push to the head branch. For a pull request into
   `main`, run it only after the candidate's **Build and Deploy to EKS** run
   passes.
2. After the merge, open a test pull request into that branch to confirm the
   `gate` check runs, then require it. On `main`, also require up-to-date
   branches.

## Normal promotion: `develop` to `stage` to `main`

1. Merge a reviewed `develop` to `stage` PR with a merge commit. Check its
   `gate` and required CI results. Record the `stage` commit.
2. Wait for **Tag Release Candidate** to create `v<version>-rc.<N>` from that
   commit. Record the tag, commit, and workflow run. A failed or incomplete
   **Build and Deploy to EKS** run is not a validated candidate.
3. Approve the candidate's **Deploy to Production** job when it waits on the
   `production` environment. The candidate is validated only when its whole
   **Build and Deploy to EKS** run concludes `success`, including CI, Helm
   checks, image scan, provenance verification, **Direct Upgrade (latest-final)**
   and **Direct Upgrade (datev)**, **Promote Scanned Digest to Release Tags**, **Deploy to
   Production**, and **Record Validated Release Candidate**. The last job
   creates the `Release candidate v<version>-rc.<N>` prerelease, which records
   the run, commit, and pinned image reference. Then run the
   [smoke checks](#smoke-checks) against that digest.
   When Datev runs the latest final release, its upgrade job records that the
   latest-final job already covers the same baseline.
4. Do not change `stage` after the candidate you intend to promote. Every push
   to `stage` tags a new RC, and the final commit must have the same file tree
   as the highest-numbered RC; any difference, documentation included, fails
   the release. An older successful RC cannot stand in for a newer failed one,
   so validate the new candidate.
5. Merge a reviewed `stage` to `main` PR with a merge commit after `gate`
   confirms that its head is the latest validated RC, and before the RC run's
   artifacts expire. Record the PR and merge commit. Wait for any approval the
   `release` environment requires and for **Release-plz release** to create
   `v<version>`.
6. In the final tag's **Build and Deploy to EKS** run, confirm **Resolve Image
   Source** names the validated RC and run, the **Build and Push Docker Image to
   GHCR** jobs are skipped, the image is rescanned, and tag promotion succeeds.
   Approve **Deploy to Production**. Compare the final `fscert` tag, deployed
   image, and RC prerelease record: all must resolve to the same index digest.
   Confirm provenance names the RC ref, not the final ref. Confirm **Final
   Release Baseline Preflight** passes after tag promotion; it uses disposable
   kind infrastructure and does not promote or deploy anything. Investigate a
   failure before the next RC. Run the
   [smoke checks](#smoke-checks) and record the final run, digest, Helm
   revision, and results.
7. Back-merge `main` into `develop` with a merge commit, using the branch
   method in [Contributing](../CONTRIBUTING.md#release-and-versioning).
   Confirm the final tag is in `develop` history before the next release-plz
   run.

If a gate, scan, direct upgrade, migration, readiness check, digest comparison,
or smoke check fails, stop promotion and investigate that failure. A later
candidate is needed after any change to `stage`. Follow the runbook before
rolling back a release that may have applied a migration.

### Smoke checks

Run these after each RC and final deployment, in addition to the runbook's
[verification commands](deployment-runbook.md#verification):

- [ ] The Deployment pins the expected digest. The output must end in
  `@<index digest>`:

  ```bash
  kubectl get deployment statuslist-status-list-server-deployment -n statuslist \
    -o jsonpath='{.spec.template.spec.containers[0].image}'
  ```

- [ ] `/health/ready` on the admin listener returns `200`. Reach it with
  `kubectl port-forward` to the internal service; do not expose the admin port.
- [ ] A status list that existed before the upgrade still returns `200` with a
  token from the public listener:

  ```bash
  curl -fsS -o /dev/null -w '%{http_code}\n' \
    -H 'Accept: application/statuslist+jwt' \
    https://<public host>/api/v1/status-lists/<list_id>
  ```

## Hotfix path

Validate the path without creating a second live release unless a real hotfix
is needed:

- [ ] Record a CI run of the release-script tests in `scripts/tests/`. The gate
  cases in `test_promotion_gate.py` cover a hotfix without a newer version,
  without a validated RC, missing current `main`, and a head that differs from
  the latest RC. The final-path cases in `test_resolve_rc.py` cover selection
  of the highest RC without fallback and refusal of a different file tree.
  `test_release_candidate_workflow.py` covers the hotfix dispatch trigger.
- [ ] While no other release-plz PR is open, create a scratch `hotfix/*` branch
  from the released `main` commit and dispatch **Release-plz PR** on it.
  `hotfix/*` creation is restricted by a ruleset, so an actor allowed to
  bypass it creates the branch.
  Confirm it prepares a newer patch version and changelog, then close the PR
  without merging and delete the branch. Do not dispatch **Tag Release
  Candidate** on it: that tags and deploys.
- [ ] In a local clone, rehearse the back-merge of a hotfix into a `develop`
  that already holds a newer prepared version. Confirm the resolution keeps
  the development version, adds the hotfix changelog section, and keeps the
  hotfix commit in `develop` history. The prepared `develop` version must stay
  newer than the hotfix version.

If a real hotfix is released, record its RC, final digest, EKS checks, and
back-merge using the normal-promotion evidence fields below.

## Evidence and cleanup

Add a short record to the release's tracking issue or release record. Leave
fields blank until the corresponding validation has actually run. The RC
prerelease created by **Record Validated Release Candidate** already holds the
candidate's run, commit, and image reference; link it instead of copying them.

| Evidence | Link or value |
| --- | --- |
| Release window and approvers | |
| Preflight results and database backup reference | |
| Gate bootstrap output, if a branch lacked the gate | |
| Release-plz PR and prepared version | |
| `develop` to `stage` PR, gate run, and stage commit | |
| RC tag, tagging run, and RC prerelease record | |
| RC deploy run, approval, and both direct-upgrade results | |
| RC deployed Helm revision and smoke-check results | |
| `stage` to `main` PR, gate run, and merge commit | |
| Release approval, final tag, and final deploy run | |
| Final baseline preflight result | |
| Final tag and deployed digest comparison with the RC | |
| Final Helm revision and smoke-check results | |
| `main` to `develop` back-merge PR and merge commit | |
| Hotfix validation test run and outcomes | |
| Cleanup performed and remaining follow-ups | |

Remove only scratch branches, closed scratch release-plz PRs, and local
rehearsal clones. Never delete `v*` tags, including superseded or failed RCs:
the final release promotes the highest-numbered RC, so deleting a failed one
would make an older candidate eligible again. Keep the final tag, GitHub
releases, recorded digests, and run links as release evidence. If the first
file-backed rollout used list-quota transition mode, run the
[recount and enable steps](troubleshooting.md#upgrading-to-the-list-quota)
afterward and remove the transition flag as the
[file-backed signing runbook](deployment-runbook.md#existing-eks-release-with-file-backed-signing)
describes.
