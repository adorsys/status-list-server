# AWS OIDC Deployment Setup

This document explains how `deploy.yml` authenticates to AWS to deploy to
EKS, replacing the previous long-lived `AWS_ACCESS_KEY_ID` /
`AWS_SECRET_ACCESS_KEY` secrets with short-lived credentials obtained via
GitHub's OpenID Connect (OIDC) provider. See issue #236 for the original
problem statement.

## Why

`deploy-to-eks` already requested `permissions: { id-token: write }` but
then authenticated with static AWS keys pulled from repository secrets.
That meant:

- The `id-token: write` permission was requested but never used.
- The static keys never rotated, and had to be managed manually even
  during long dormant periods.
- Anyone with access to the keys (or a leak of them) could assume the same
  privileges from anywhere, indefinitely.

Switching to `role-to-assume` means AWS issues a token that is valid only
for the duration of the job, tied to a specific GitHub Actions run.

## How it's wired together

Infrastructure for the OIDC trust relationship lives in the
`wallet-eks-env` Terraform repository, in
`terraform/modules/github-actions-oidc`. It creates:

1. **`aws_iam_openid_connect_provider`** for
   `https://token.actions.githubusercontent.com` (one per AWS account).
2. **`aws_iam_role.deploy_role`** with a trust policy that requires *all*
   of the following to be true before AWS will hand out credentials:
   - `token.actions.githubusercontent.com:aud` = `sts.amazonaws.com`
   - `token.actions.githubusercontent.com:sub` =
     `repo:adorsys/status-list-server:environment:production`
   - `token.actions.githubusercontent.com:ref` = `refs/heads/main`

   Both the `sub` (environment) and `ref` (branch) claims are enforced by
   the IAM trust policy itself, not just by workflow-level conditionals.
   A workflow running on a feature branch, or one that does not reference
   the `production` GitHub environment, cannot assume this role even if
   the workflow YAML were modified to try, because the check happens on
   AWS's side during `AssumeRoleWithWebIdentity`.
3. An **EKS access entry** (`aws_eks_access_entry` /
   `aws_eks_access_policy_association`) that grants the role
   `AmazonEKSEditPolicy` scoped to the `statuslist` namespace — no
   `aws-auth` ConfigMap edits required.
4. A **`github_repository_environment`** (via the `integrations/github`
   Terraform provider) named `production` with:
   - `deployment_branch_policy` restricted to the `main` branch via
     `github_repository_environment_deployment_policy`.
   - Optional required reviewers (`required_reviewer_user_ids` /
     `required_reviewer_team_ids` module variables) enforcing a manual
     approval gate before a deployment run can proceed.

The role's ARN is exposed as the `github_actions_deploy_role_arn` Terraform
output.

In this repository, `deploy.yml`:

- Runs `deploy-to-eks` under `environment: production`, which is what
  makes GitHub attach `environment:production` to the OIDC token's `sub`
  claim and what triggers the environment's approval gate.
- Uses `aws-actions/configure-aws-credentials` with
  `role-to-assume: ${{ vars.AWS_DEPLOY_ROLE_ARN }}` instead of static keys.
- Adds a `verify-ci` job that calls `CI.yml` as a reusable workflow and
  gates `deploy-to-eks` on it succeeding, so a deploy cannot proceed if CI
  is red on `main`.
- Restricts `deploy-to-eks` to `github.ref == 'refs/heads/main'`, matching
  the trust policy's `ref` condition (tag pushes still build and push the
  Docker image, they just don't trigger a Kubernetes deploy).

## One-time setup

1. **Apply the Terraform module** in `wallet-eks-env/production` (it's
   already wired into `main.tf` as `module.github_actions_oidc`):

   ```bash
   cd wallet-eks-env/production
   terraform init
   terraform apply
   ```

   If an OIDC provider for `token.actions.githubusercontent.com` already
   exists in the target AWS account (created manually or by another
   workspace), import it first instead of letting Terraform create a
   duplicate:secret_arn

   ```bash
   terraform import module.github_actions_oidc.aws_iam_openid_connect_provider.github \
     arn:aws:iam::<account-id>:oidc-provider/token.actions.githubusercontent.com
   ```

   Terraform's `github` provider needs a token with repo admin rights,
   supplied via `GITHUB_TOKEN` (or `GITHUB_APP_*`) in the environment —
   never commit it to `.tf` files or `terraform.tfvars`.

2. **Read the role ARN from the Terraform output** and set it as a
   repository (or `production` environment) **variable** — not a secret,
   since the ARN itself isn't sensitive; the trust policy is what protects
   it:

   ```bash
   terraform output -raw github_actions_deploy_role_arn
   ```

   In GitHub: *Settings → Secrets and variables → Actions → Variables* →
   add `AWS_DEPLOY_ROLE_ARN`.

3. **Configure the `production` environment's approval gate** (if not set
   via the `required_reviewer_user_ids` / `required_reviewer_team_ids`
   Terraform variables): *Settings → Environments → production → Required
   reviewers*.

4. **Verify OIDC works** by pushing to `main` and confirming
   `deploy-to-eks` succeeds using `role-to-assume`.

5. **Delete the static credentials** once verified: remove the
   `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` repository secrets, and
   deactivate/delete the corresponding IAM user access keys in AWS.

## References

- [Configuring OpenID Connect in Amazon Web Services](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-amazon-web-services)
- [Creating a role for web identity federation (OIDC)](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-idp_oidc.html)
- [Managing environments for deployment](https://docs.github.com/en/actions/deployment/targeting-different-environments/using-environments-for-deployment)
