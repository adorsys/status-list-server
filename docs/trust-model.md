# Status List Token trust model

The server signs Status List Tokens with its configured token-signing key and
certificate chain. Registered issuer public keys authenticate management writes;
they are not the server's token-signing keys. An authenticated issuer controls
its own lists, while the server acts as the status provider publishing those
lists to relying parties.

## Sandbox trust boundary

The hosted sandbox is a non-production trust domain. Its status lists, issuers,
and tokens are test-only. Production relying parties must not trust the sandbox
signing certificate or key, even if its transport TLS certificate chains to a
publicly trusted CA. A valid signature proves possession of a signing key; it
does not authorize that key to assert production credential status.

Use a dedicated sandbox hostname, signing key and certificate chain, registry,
management-token audience, namespace, and database storage. Never copy production
private keys or issuer trust registries into the sandbox. `server.profile=hosted`
adds SQL-backed issuers to key resolution; it does not itself create these
infrastructure boundaries.

JWT status tokens carry `x5c`; CWT tokens carry the certificate chain in COSE.
Relying parties must validate the signature and chain against an explicitly
approved status-signing identity for the referenced list URL. Do not trust a
chain merely because it was embedded in a token. Bind acceptance to the expected
status provider and URL, validate token time claims, and keep sandbox trust
configuration separate from production.

The status token's `sub` names the public status-list URL. The referenced
credential points to that URL and its status index; that index selects an entry
in the list. Do not interpret the URL or possession of a token as permission to
write or to administer an issuer. Management JWTs have their own required type,
issuer ownership, audience, lifetime, and registered public-key checks.

## Rotation

Filesystem deployments load the signing key and chain from the configured store
paths; cloud builds can use their configured secrets backend and ACME certificate
management. Rotate through the selected backend's supported mechanism, preserving
the match between private key and certificate. See
[secret backends](secrets-backends.md) and [DNS providers](dns-providers.md).

Coordinate relying-party trust updates before changing signing identities.
Relying parties must retain an approved previous verification identity for tokens
that may remain valid or cached, then retire it according to their token validity
and cache policy. Certificate renewal and key rotation do not automatically grant
trust to a new status provider. There is no automatic distribution of relying-party
trust configuration; operators must arrange it with consumers. Sandbox rotation
must never introduce a production signing identity.

See the [hosted deployment guide](hosted-sandbox.md) for certificate mounts,
ingress separation, and deployment verification.
