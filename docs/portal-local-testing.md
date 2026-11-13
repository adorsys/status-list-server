# Testing the Status List Portal against a local server

This guide runs the [Status List Portal](https://github.com/ADORSYS-GIS/status-list-portal) against a hosted server built from this checkout, so you can register and manage sandbox issuers end to end. Every page of the portal calls this server's admin API, and every issuer it registers publishes to this server's management API.

| Process | Address | What it is |
| --- | --- | --- |
| Status List Server, public API | <http://localhost:8000> | Where anyone reads status lists |
| Status List Server, management API | <http://localhost:8001> | Where the portal's issuers publish status lists |
| Status List Server, admin API | <http://localhost:8002> | Where the portal creates and changes issuers |
| Portal | <http://localhost:8080> | The portal's backend and its built frontend |

To check the same admin API calls automatically, without the portal, run the [hosted profile check](api-testing.md#hosted-profile-check).

## Prerequisites

- **Both checkouts side by side**, this one and the portal:

  ```sh
  git clone https://github.com/ADORSYS-GIS/status-list-portal.git ../status-list-portal
  ```

- **Rust.** This checkout's `rust-toolchain.toml` selects the server's toolchain. The portal needs Rust 1.99 or later: run `rustup update stable`.
- **cmake and Go**, which the server's crypto library needs to build (`sudo apt-get install -y cmake golang-go` on Ubuntu).
- **Docker**, for the portal's PostgreSQL: run `docker compose up -d` in the portal checkout. It listens on `POSTGRES_PORT`, 5432 by default. Use your own port wherever this guide says 5432.
- **Bun**, to build the portal's frontend, and **Node.js 22 or later**, to make an issuer's key pair.
- **A GitHub account**, to create the OAuth app the portal signs you in with.

## Step 1: start the server

The portal creates issuers through the admin API, which only the hosted profile allows. Hosted mode needs a SQL backend; this guide uses a SQLite file, so the server needs no database service.

1. In this checkout, write a registry that lists the portal as an admin. `issuer-registry/` is ignored by Git:

   ```sh
   mkdir -p issuer-registry
   cat > issuer-registry/issuers.yaml <<'EOF'
   version: 1
   issuers: []
   admins:
     - id: portal
       scopes: ['issuers:read', 'issuers:write']
       keys:
         - kid: test-admin-key
           alg: ES256
           jwk:
             kty: EC
             crv: P-256
             x: GtkCNIXEFHQ8j_gwyoS0H9eZQGCI_Iaqm2wUymJvOfQ
             y: D9yk2oGE-yZjX50UqD1j68vpRbEhM-WyuhAWrEPAcyI
   EOF
   ```

   The key is the public half of the portal's `test_data/admin-keys/es256.pem`, a throwaway key its tests sign admin tokens with. Its private half is public, so use this registry only on your own machine.

2. Start the server, and leave this terminal open. The first build takes several minutes:

   ```sh
   APP_SERVER__PROFILE=hosted \
   APP_DATABASE__BACKEND=sqlite \
   APP_DATABASE__URL='sqlite://issuer-registry/status-list.db?mode=rwc' \
   APP_MANAGEMENT_AUTH__ISSUERS_FILE=issuer-registry/issuers.yaml \
   APP_ADMIN_AUTH__AUDIENCES=test-admin-audience \
   APP_MANAGEMENT_AUTH__AUDIENCES=test-management-audience \
   APP_SERVER__CERT__PROVISIONING_STRATEGY=store \
   APP_SERVER__CERT__STORE__CERTIFICATE_PATH=test_data/ed25519_cert.pem \
   APP_SERVER__CERT__STORE__SIGNING_KEY_PATH=test_data/ed25519_key.pem \
   cargo run --features sqlite
   ```

3. In another terminal, check that it is ready. It prints `200`:

   ```sh
   curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8002/health/ready
   ```

| Setting | Value | Why |
| --- | --- | --- |
| `APP_SERVER__PROFILE` | `hosted` | Portal issuers exist only in the hosted profile |
| `APP_DATABASE__BACKEND`, `APP_DATABASE__URL` | SQLite in `issuer-registry/` | Hosted issuers live in SQL storage |
| `APP_MANAGEMENT_AUTH__ISSUERS_FILE` | `issuer-registry/issuers.yaml` | Lists the portal as admin `portal` with key `test-admin-key` |
| `APP_ADMIN_AUTH__AUDIENCES` | `test-admin-audience` | The audience the portal's admin tokens carry |
| `APP_MANAGEMENT_AUTH__AUDIENCES` | `test-management-audience` | The audience issuers' management tokens carry; it differs from the admin one |
| Certificate paths | `test_data/ed25519_*.pem` | The development key the server signs status lists with |

## Step 2: configure the portal's `.env`

The portal refuses to start until three values in its `.env` are set. `.env` is ignored by Git; never commit it.

| Variable | What it is | Where it comes from |
| --- | --- | --- |
| `APP_GITHUB__CLIENT_ID` | Identifies the portal to GitHub when someone signs in | Your GitHub OAuth app |
| `APP_GITHUB__CLIENT_SECRET` | Proves to GitHub that the request comes from the portal | Your GitHub OAuth app, shown once |
| `APP_SESSION__KEY` | Encrypts session cookies: 64 random bytes in hex | `openssl rand -hex 64` |

1. In the portal checkout, create `.env` from the template, if you don't have one yet:

   ```sh
   cd ../status-list-portal
   cp .env.template .env
   ```

2. Generate the session key and write it into `.env`. Changing it later signs everyone out:

   ```sh
   sed -i "s/^APP_SESSION__KEY=.*/APP_SESSION__KEY=$(openssl rand -hex 64)/" .env
   ```

3. Create the GitHub OAuth app. Open <https://github.com/settings/applications/new> (GitHub → Settings → Developer settings → OAuth Apps → New OAuth App) and fill in:

   | Field | Value |
   | --- | --- |
   | Application name | Anything, such as `Status List Portal (local)` |
   | Homepage URL | `http://localhost:8080` |
   | Authorization callback URL | `http://localhost:8080/api/v1/session/github/callback` |

4. Click **Register application**. Copy the **Client ID**, then click **Generate a new client secret** and copy the secret right away: GitHub shows it only once.

5. Put both into `.env`:

   ```sh
   APP_GITHUB__CLIENT_ID=<the client ID>
   APP_GITHUB__CLIENT_SECRET=<the client secret>
   ```

6. Check the other values the local setup relies on:

   ```sh
   APP_SERVER__ORIGIN=http://localhost:8080
   APP_SERVER__FRONTEND_DIR=frontend/build
   APP_DATABASE__URL=postgres://postgres:postgres@localhost:5432/portal
   ```

The callback URL must be exactly `APP_SERVER__ORIGIN` followed by `/api/v1/session/github/callback`, or GitHub refuses the sign-in. Leave the `APP_ADMIN_API__*` and `APP_MANAGEMENT_API__*` values as they are; step 3 sets them on the command line.

## Step 3: start the portal

The portal must sign its admin tokens with the key and audience the registry expects. The settings on the command line take precedence over `.env`.

1. In the portal checkout, build the frontend once, so the backend can serve it:

   ```sh
   bun install && bun run build
   ```

2. Start the portal, and leave this terminal open:

   ```sh
   APP_ADMIN_API__URL=http://localhost:8002 \
   APP_ADMIN_API__PRINCIPAL=portal \
   APP_ADMIN_API__AUDIENCE=test-admin-audience \
   APP_ADMIN_API__KEY_ID=test-admin-key \
   APP_ADMIN_API__SIGNING_KEY_FILE=test_data/admin-keys/es256.pem \
   APP_MANAGEMENT_API__URL=http://localhost:8001 \
   APP_MANAGEMENT_API__AUDIENCE=test-management-audience \
   cargo run -- server
   ```

3. Check that it is ready. It prints `200`, after a few minutes on the first build:

   ```sh
   curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8080/health/ready
   ```

| Portal setting | Must match on the server |
| --- | --- |
| `APP_ADMIN_API__PRINCIPAL=portal` | The admin's `id` in `issuers.yaml` |
| `APP_ADMIN_API__KEY_ID=test-admin-key` | That admin's key `kid` |
| `APP_ADMIN_API__SIGNING_KEY_FILE` | The private half of that key's `jwk` |
| `APP_ADMIN_API__AUDIENCE=test-admin-audience` | `APP_ADMIN_AUTH__AUDIENCES` |
| `APP_MANAGEMENT_API__AUDIENCE=test-management-audience` | `APP_MANAGEMENT_AUTH__AUDIENCES` |

If any of them differs, the server answers the portal's calls with `invalid_token`, and the portal answers 502.

## Step 4: test it in the browser

Open <http://localhost:8080> and walk through a sandbox issuer's whole life. Each step calls this server's admin API.

### Sign in

The home page explains the sandbox. Click **Sign in with GitHub** and authorize the OAuth app.

![The portal's home page, signed out, with Sign in with GitHub](assets/portal-local-testing/home.png)

### Register an issuer

Accept the terms of use if asked, then open **Register an issuer**. Enter a display name, keep **ES256**, and paste the public key as a JSON Web Key. **Register issuer** makes the portal call `createIssuer`.

![The Register an issuer form: display name, algorithm and public key](assets/portal-local-testing/register.png)

#### Generate the key pair

The form needs the issuer's **public** key as a JSON Web Key. This is the script the portal shows under **Need a key pair?**, for ES256.

1. Make an empty folder for the issuer's keys, outside both checkouts:

   ```sh
   mkdir -p ~/sandbox-issuer && cd ~/sandbox-issuer
   ```

2. Save the script as `make-key.mjs`:

   ```sh
   cat > make-key.mjs <<'EOF'
   // make-key.mjs: run `node make-key.mjs` (Node.js 22 or later).
   import { writeFile } from 'node:fs/promises';

   const { privateKey, publicKey } = await crypto.subtle.generateKey(
     { name: 'ECDSA', namedCurve: 'P-256' },
     true,
     ['sign', 'verify'],
   );
   // Keep private-key.json to yourself: it signs your issuer's tokens. The script refuses to
   // overwrite one you already have.
   await writeFile('private-key.json', JSON.stringify(await crypto.subtle.exportKey('jwk', privateKey)), {
     mode: 0o600,
     flag: 'wx',
   });
   console.log(JSON.stringify(await crypto.subtle.exportKey('jwk', publicKey)));
   EOF
   ```

3. Run it. It saves the private key in `private-key.json` and prints the public key:

   ```sh
   node make-key.mjs
   ```

4. Paste the printed line, which looks like `{"key_ops":["verify"],"ext":true,"kty":"EC","x":"…","y":"…","crv":"P-256"}`, into **Public key**.

Never paste `private-key.json`: the portal refuses a private key. Each issuer needs its own key pair, because the server answers `409 key_material_in_use` to a key it has registered before. For a second issuer, run the script in another folder.

### Read the issuer's details

The portal confirms that the issuer is ready and shows what its tokens need:

- **Issuer id (iss)**: assigned by the server.
- **Key id (kid)**: the key's thumbprint, computed by the server.
- **Audience (aud)**: `test-management-audience`.
- **Management API**: `http://localhost:8001`.
- **Expires**: 30 days from now, the sandbox lifetime.

![A new issuer's page: its id, kid, audience, management API and expiry](assets/portal-local-testing/issuer.png)

### Publish a status list

In the folder with `private-key.json`, save the page's `mint-token.mjs` script. Then run the page's **Publish a status list** commands. The management API checks the token they send, so a `2xx` answer proves the issuer works end to end.

![The mint-token.mjs script and the commands that publish a status list, above the Renew and Delete buttons](assets/portal-local-testing/publish.png)

### Manage the issuer

**Your issuers** lists every issuer of the account, with its state and expiry.

![Your issuers: one active issuer, expiring in 30 days](assets/portal-local-testing/issuers.png)

On an issuer's page:

- **Renew for 30 days** sends a conditional change with `If-Issuer-Version`; the expiry moves forward.
- **Delete issuer** suspends it; it stays listed as **Suspended**, and its tokens stop working.

## Stop and clean up

Press Ctrl+C in the portal's and the server's terminals. To start the next run with no issuers, delete the server's database while the server is stopped:

```sh
rm -f issuer-registry/status-list.db*
```

## Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| The portal fails to build: `rustc … is not supported` | Rust is older than 1.99 | `rustup update stable` |
| The server exits: `server.profile=hosted requires a durable SQL backend` | It runs without `APP_DATABASE__BACKEND=sqlite` | Use the command in step 1 as it is |
| The portal answers 502 on every issuer page | The portal's admin settings don't match the registry | Compare them with the table in step 3 |
| Registering answers 409 | That public key is registered already | Generate a new key pair |
| Publishing a status list answers 401 | The token's `aud` or `kid` is wrong, or it expired after two minutes | Copy the script again from the issuer's page, and mint a fresh token |
