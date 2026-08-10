# Certificate Object Storage

Certificate material is stored through the certificate manager `Storage` trait. The S3-compatible backend supports MinIO, Ceph/RadosGW, and generic services that implement the S3 API.

## Cargo Features

- `aws`: AWS S3 for certificate data plus AWS Secrets Manager for signing keys and ACME account data.
- `s3-compatible`: S3-compatible object storage for certificate data, signing keys, and ACME account data.
- `redis`: optional distributed cache for certificate data reads when using the AWS S3 path.

Build example:

```bash
cargo build --features postgres,acme,s3-compatible
```

## Configuration

Select the backend with:

```bash
APP_SERVER__CERT__STORAGE_BACKEND=s3_compatible
```

S3-compatible settings:

```bash
APP_S3_COMPATIBLE__ENDPOINT_URL=http://minio.example.com:9000
APP_S3_COMPATIBLE__REGION=us-east-1
APP_S3_COMPATIBLE__BUCKET=status-list-certs
APP_S3_COMPATIBLE__KEY_PREFIX=status-list/certificates
APP_S3_COMPATIBLE__FORCE_PATH_STYLE=true
APP_S3_COMPATIBLE__AUTO_CREATE_BUCKET=true
APP_S3_COMPATIBLE__ACCESS_KEY_ID=minioadmin
APP_S3_COMPATIBLE__SECRET_ACCESS_KEY=minioadmin
```

Credentials can also come from the standard AWS SDK environment and credential-chain variables. The explicit `APP_S3_COMPATIBLE__ACCESS_KEY_ID` and `APP_S3_COMPATIBLE__SECRET_ACCESS_KEY` values take precedence when both are set.

Treat the configured bucket as sensitive. With `s3_compatible`, the bucket stores certificate JSON, signing keys, and ACME account data. Use private buckets, TLS endpoints, restricted credentials, and server-side encryption where your object storage supports it.

## Object Keys

The certificate manager writes logical keys:

- `certs-<registrable-domain>-cert_data.json`: serialized certificate chain metadata.
- `keys-<domain-list>`: PKCS#8 PEM signing key.
- `acme_accounts-<registrable-domain>`: ACME account credentials.

The storage backend prepends `APP_S3_COMPATIBLE__KEY_PREFIX` after trimming leading/trailing slashes. For example:

```text
APP_S3_COMPATIBLE__KEY_PREFIX=status-list/certificates
logical key=certs-example.com-cert_data.json
object key=status-list/certificates/certs-example.com-cert_data.json
```

## MinIO Example

Run MinIO locally:

```bash
docker run --rm \
  --name status-list-minio \
  -p 9000:9000 \
  -e MINIO_ROOT_USER=minioadmin \
  -e MINIO_ROOT_PASSWORD=minioadmin \
  minio/minio:RELEASE.2025-09-07T16-13-09Z server /data
```

Run the server against MinIO:

```bash
APP_SERVER__CERT__STORAGE_BACKEND=s3_compatible \
APP_S3_COMPATIBLE__ENDPOINT_URL=http://127.0.0.1:9000 \
APP_S3_COMPATIBLE__REGION=us-east-1 \
APP_S3_COMPATIBLE__BUCKET=status-list-certs \
APP_S3_COMPATIBLE__KEY_PREFIX=status-list/certificates \
APP_S3_COMPATIBLE__FORCE_PATH_STYLE=true \
APP_S3_COMPATIBLE__AUTO_CREATE_BUCKET=true \
APP_S3_COMPATIBLE__ACCESS_KEY_ID=minioadmin \
APP_S3_COMPATIBLE__SECRET_ACCESS_KEY=minioadmin \
cargo run --features memory,acme,s3-compatible
```

Kubernetes secret for Helm:

```bash
kubectl create namespace statuslist
kubectl create secret generic statuslist-minio-credentials \
  --namespace statuslist \
  --from-literal=access-key-id=minioadmin \
  --from-literal=secret-access-key=minioadmin
```

Render the chart with MinIO settings:

```bash
helm dependency update ./helm/chart
helm template statuslist ./helm/chart \
  --namespace statuslist \
  -f ./helm/chart/values.yaml \
  -f ./helm/chart/values-minio.yaml
```

## Ceph/RadosGW And Generic S3

Use the RadosGW endpoint URL and credentials issued for the bucket. Most Ceph/RadosGW deployments should keep path-style addressing enabled:

```bash
APP_SERVER__CERT__STORAGE_BACKEND=s3_compatible
APP_S3_COMPATIBLE__ENDPOINT_URL=https://rgw.example.com
APP_S3_COMPATIBLE__REGION=us-east-1
APP_S3_COMPATIBLE__BUCKET=status-list-certs
APP_S3_COMPATIBLE__KEY_PREFIX=prod/certificates
APP_S3_COMPATIBLE__FORCE_PATH_STYLE=true
APP_S3_COMPATIBLE__AUTO_CREATE_BUCKET=false
```

Set `APP_S3_COMPATIBLE__AUTO_CREATE_BUCKET=false` when the bucket is managed by infrastructure automation or the endpoint does not support bucket creation.
