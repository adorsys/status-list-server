#!/usr/bin/env bash
#
# deploy-local-esm.sh — deploy the status-list-server chart to the LOCAL emulation
# (floci + Minikube) provided by ADORSYS-GIS/wallet-eks-env PR #47, exercising the
# ESO fix from issue #586: point the release at a cluster-scoped store served by the
# External Secrets Operator instead of rendering a namespaced SecretStore.
#
# Prereqs (from wallet-eks-env PR #47):
#   - wallet-eks-env checked out with the PR applied, environment already up:
#       cp .env.local.example .env.local   # set your values
#       bash scripts/local-env.sh up
#   - The floci endpoint (default http://localhost:4566) and the emulated Minikube
#     profile (default wallet-local). kubeconfig is ~/.kube/config.
#
# Usage:
#   bash scripts/deploy-local-esm.sh [--image ghcr.io/adorsys/status-list-server:1.2.0-fscert]
#
# Notes:
#   - The emulation's SecretStore (terraform/modules/kubernetes/secretstore.yaml) is a
#     NAMESPACED store in datev-wallet. Our cross-namespace reference from
#     statuslist-production needs a CLUSTER store, so this script applies a
#     ClusterSecretStore named datev-secret-store (the infra-side mirror of #586).
#   - The emulated ESO serves external-secrets.io/v1 and its AWS provider has no
#     per-store endpoint field. To exercise live secret sync against floci, set
#     AWS_ENDPOINT_URL (and the floci creds) on the ESO controller deployment in the
#     datev-wallet namespace first; otherwise the release still deploys but the
#     ExternalSecrets stay pending on sync.
#   - The chart templates use external-secrets.io/v1, so the emulated ESO must serve
#     that API version. wallet-eks-env PR #47 pins ESO 0.11.0 (v1beta1 only); upgrade
#     it to >= 0.16.0 first: `helm upgrade external-secrets external-secrets/external-secrets
#     --kube-context=$MINIKUBE_PROFILE --namespace datev-wallet --version 0.16.0
#     --set installCRDs=true --set serviceAccount.create=false --set serviceAccount.name=external-secrets-sa`.
#   - Local-only overrides applied by this script: serviceMonitor/prometheusRule off
#     (no Prometheus CRDs in Minikube), autoscaling off (values-production enables HPA),
#     postgres storageClass=standard (values-aws.yaml sets high-performance, which
#     needs the EBS CSI driver absent from Minikube), and a self-signed certificate
#     mounted for the app's cert_store readiness check.
#   - The default image is the fscert variant, which reads its signing certificate and
#     key from the mounted filesystem (APP_SERVER__CERT__STORE__*_PATH) and so comes
#     Ready in the emulation. The aws variant instead fetches its signing material from
#     AWS Secrets Manager (setup.rs:925) and therefore stays not-Ready locally (that
#     backend is unreachable in the emulator) -- that is inherent to the aws image, not
#     the ESO fix. Override IMAGE to test the aws variant; the ESO fix (ClusterSecretStore
#     + ExternalSecret apply) is image-independent and is exercised either way.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CHART_DIR="$REPO_ROOT/deploy/helm/chart"
HELM_RELEASE_NAME="statuslist"
HELM_NAMESPACE="statuslist-production"

# Emulation settings (mirror wallet-eks-env .env.local.example defaults).
MINIKUBE_PROFILE="${MINIKUBE_PROFILE:-wallet-local}"
FLOCI_ENDPOINT="${FLOCI_ENDPOINT:-http://localhost:4566}"
FLOCI_REGION="${FLOCI_REGION:-eu-central-1}"
CLUSTER_STORE_NAME="${CLUSTER_STORE_NAME:-datev-secret-store}"

# Default image: the fscert variant comes Ready in the emulation (filesystem cert
# store). See the header note on the aws variant.
IMAGE="${IMAGE:-ghcr.io/adorsys/status-list-server:1.2.0-fscert}"

KUBECTL=(kubectl --context="$MINIKUBE_PROFILE")

for t in helm kubectl docker; do
  command -v "$t" >/dev/null 2>&1 || { echo "ERROR: missing required tool: $t" >&2; exit 1; }
done

"${KUBECTL[@]}" cluster-info >/dev/null 2>&1 \
  || { echo "ERROR: Minikube context '$MINIKUBE_PROFILE' not reachable. Start the emulation first (bash scripts/local-env.sh up)." >&2; exit 1; }

# 1. Ensure the namespace the release targets exists.
"${KUBECTL[@]}" get namespace "$HELM_NAMESPACE" >/dev/null 2>&1 \
  || "${KUBECTL[@]}" create namespace "$HELM_NAMESPACE"

# 2. Apply a ClusterSecretStore named datev-secret-store so the ExternalSecrets in
#    statuslist-production can reference a cluster-scoped store cross-namespace.
#    This mirrors the required infra change tracked in issue #586 (the emulation's
#    stock secretstore.yaml is namespaced to datev-wallet and cannot be referenced
#    from statuslist-production).
#
#    The emulated ESO serves the external-secrets.io/v1 API (not v1beta1), and the
#    AWS provider spec has no `endpoint` field -- ESO reaches the AWS region through
#    the operator's own AWS_ENDPOINT_URL / IRSA wiring, not per-store. To test live
#    secret sync against floci, set AWS_ENDPOINT_URL on the ESO controller deployment
#    first (see the script header); without it the store still applies and the release
#    deploys, but ExternalSecrets stay pending on sync.
cat <<EOF | "${KUBECTL[@]}" apply -f -
apiVersion: external-secrets.io/v1
kind: ClusterSecretStore
metadata:
  name: ${CLUSTER_STORE_NAME}
spec:
  provider:
    aws:
      service: SecretsManager
      region: ${FLOCI_REGION}
EOF

# 3. Build chart dependencies.
helm repo add open-telemetry https://open-telemetry.github.io/opentelemetry-helm-charts >/dev/null 2>&1 || true
helm dependency build "$CHART_DIR" >/dev/null

# 4. Deploy with the CI-equivalent ESO fix: reference the ClusterSecretStore and do
#    NOT render a namespaced SecretStore (matches .github/workflows/deploy.yml).
echo "==> Deploying $HELM_RELEASE_NAME to $HELM_NAMESPACE (ClusterSecretStore=$CLUSTER_STORE_NAME)"
helm upgrade --install "$HELM_RELEASE_NAME" "$CHART_DIR" \
  --namespace "$HELM_NAMESPACE" \
  -f "$CHART_DIR"/values-aws.yaml \
  -f "$CHART_DIR"/values-production.yaml \
  --set-string "externalSecret.spec.secretStoreRef.name=${CLUSTER_STORE_NAME}" \
  --set-string "externalSecret.spec.secretStoreRef.kind=ClusterSecretStore" \
  --set "secretStore.enabled=false" \
  --set-json 'externalSecret.spec.target.template={"type":"Opaque","data":{"database-password":"{{ .postgres_password }}","postgres-password":"{{ .postgres_password }}","statuslist.crt":"{{ .certificate }}","statuslist.key":"{{ .key }}"}}' \
  --set-string "statuslist.image.repository=ghcr.io/adorsys/status-list-server" \
  --set-string "statuslist.image.tag=${IMAGE##*:}" \
  --set "serviceMonitor.enabled=false" \
  --set "prometheusRule.enabled=false" \
  --set "autoscaling.enabled=false" \
  --set "postgres.persistence.storageClass=standard" \
  --set 'statuslist.secretMounts[0].name=database-credentials' \
  --set 'statuslist.secretMounts[0].secretName=statuslist-secret' \
  --set 'statuslist.secretMounts[0].mountPath=/var/run/status-list-server/database' \
  --set 'statuslist.secretMounts[0].items[0].key=postgres-password' \
  --set 'statuslist.secretMounts[0].items[0].path=password' \
  --set-string 'statuslist.secretMounts[0].fileEnv.APP_DATABASE__PASSWORD_FILE=password' \
  --set 'statuslist.secretMounts[1].name=local-signing-material' \
  --set 'statuslist.secretMounts[1].secretName=statuslist-secret' \
  --set 'statuslist.secretMounts[1].mountPath=/var/run/status-list-server/cert' \
  --set 'statuslist.secretMounts[1].items[0].key=statuslist.crt' \
  --set 'statuslist.secretMounts[1].items[0].path=statuslist.crt' \
  --set 'statuslist.secretMounts[1].items[1].key=statuslist.key' \
  --set 'statuslist.secretMounts[1].items[1].path=statuslist.key' \
  --set-string 'statuslist.secretMounts[1].fileEnv.APP_SERVER__CERT__STORE__CERTIFICATE_PATH=statuslist.crt' \
  --set-string 'statuslist.secretMounts[1].fileEnv.APP_SERVER__CERT__STORE__SIGNING_KEY_PATH=statuslist.key' \
  --timeout 3m || true

# 5. Ensure the app secrets exist so postgres and the app can start.
#
#    In the production flow the ExternalSecrets sync statuslist-secret and
#    aws-credentials-secret from the ClusterSecretStore. The floci emulator does not
#    currently complete the ESO AWS credential handshake, so the ExternalSecrets stay
#    SecretSyncedError here. As a local-only fallback, seed the secrets the Deployment
#    and bundled PostgreSQL need (password/postgres-password for the app+db,
#    credentials/config for the mounted AWS credentials volume) so the full stack comes
#    up. This is NOT part of the issue-#586 fix -- it is a stand-in for the ESO sync the
#    emulator cannot yet deliver.
if ! "${KUBECTL[@]}" get secret statuslist-secret -n "$HELM_NAMESPACE" >/dev/null 2>&1; then
  echo "==> ESO did not sync statuslist-secret; creating local fallback Secret (emulator sync limitation)"
  "${KUBECTL[@]}" create secret generic statuslist-secret -n "$HELM_NAMESPACE" \
    --from-literal=password=local-db-password \
    --from-literal=postgres-password=local-db-password \
    --from-literal=POSTGRES_PASSWORD=local-db-password
fi

# Ensure the signing certificate keys in statuslist-secret are a valid EC keypair so
# the mounted cert_store (local-signing-material) satisfies the app's readiness check.
# Always regenerated (cheap, local-only) so a stale/non-EC cert from an earlier run is
# replaced -- the app's parser rejects RSA signing keys.
echo "==> Ensuring EC signing certificate in statuslist-secret (local-only)"
CERT_DIR="$(mktemp -d)"
# EC (P-256), not RSA: the app's signing-key parser rejects RSA (unsupported OID
# 1.2.840.113549.1.1.1) and expects an elliptic-curve key.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 365 \
  -keyout "$CERT_DIR/statuslist.key" \
  -out "$CERT_DIR/statuslist.crt" \
  -subj "/CN=statuslist.local" >/dev/null 2>&1
"${KUBECTL[@]}" patch secret statuslist-secret -n "$HELM_NAMESPACE" --type=merge \
  --patch "$(cat <<PATCH
{"data":{"statuslist.crt":"$(base64 -w0 < "$CERT_DIR/statuslist.crt")","statuslist.key":"$(base64 -w0 < "$CERT_DIR/statuslist.key")"}}
PATCH
)"
rm -rf "$CERT_DIR"
if ! "${KUBECTL[@]}" get secret aws-credentials-secret -n "$HELM_NAMESPACE" >/dev/null 2>&1; then
  echo "==> ESO did not sync aws-credentials-secret; creating local fallback Secret (emulator sync limitation)"
  "${KUBECTL[@]}" create secret generic aws-credentials-secret -n "$HELM_NAMESPACE" \
    --from-literal=credentials="[default]
aws_access_key_id=test
aws_secret_access_key=test
" \
    --from-literal=config="[default]
region=eu-central-1
"
fi

echo "==> ExternalSecrets in $HELM_NAMESPACE:"
"${KUBECTL[@]}" get externalsecrets -n "$HELM_NAMESPACE"
echo "==> ClusterSecretStore:"
"${KUBECTL[@]}" get clustersecretstore "$CLUSTER_STORE_NAME"
echo "==> Waiting for postgres and the app deployment to be ready..."
"${KUBECTL[@]}" rollout status statefulset/${HELM_RELEASE_NAME}-postgres \
  -n "$HELM_NAMESPACE" --timeout 4m
"${KUBECTL[@]}" rollout status deployment/${HELM_RELEASE_NAME}-status-list-server-deployment \
  -n "$HELM_NAMESPACE" --timeout 4m

echo "Done. Pods:"
"${KUBECTL[@]}" get pods -n "$HELM_NAMESPACE"
