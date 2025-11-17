# Status List Server

The Status List Server is a web service that manages and publishes status lists, allowing issuers to update statuses and verifiers to retrieve them. It implements JWT-based authentication using ES256 (ECDSA with P-256 and SHA-256) for securing its endpoints.

## Getting Started

Before running the server, ensure you have the following tools installed:

- [Rust & Cargo](https://www.rust-lang.org/tools/install) (Latest stable version recommended).
- [PostgreSQL](https://www.postgresql.org/download/): The database system used for storing status lists.
- [Redis](https://redis.io/download): The in-memory data structure store used for caching.

**Clone the Repository:**

```bash
git clone https://github.com/adorsys/status-list-server.git
cd status-list-server
```

### Configuration

**Environment Variables:**

  Create a `.env` file in the root directory. Take a look at the [.env.template](.env.template) file for an example of the required variables.

### Running with Docker Compose

The simplest way to run the project is with [docker compose](https://docs.docker.com/compose/):

- Execute the command below at the root of the project

```sh
docker compose up --build -d
```

This command will pull all required images and start the server.

### Running Manually

To start the server, execute:

```bash
cargo run
```

By default, the server will listen on `http://localhost:8000`. You can modify the host and port in the configuration settings.

## API Endpoints

### Health Check

- **Endpoint:** `GET /health`
- **Description:** Checks the health status of the server.
- **Response:**
  - `200 OK`: Server is running.

### Register Issuer

- **Endpoint**: `POST /credentials/`
- **Description**: Allows issuers to register their public key and identifier for later authentication
- **Request Body**

  ```json
  {
    "issuer": "<issuer_id>",
    "public_key": "<public_key JWK>"
  }
  ```

  - `issuer`: Unique identifier for the issuer
  - `public_key`: Public key in JWK format with `alg` field set

### Publish Status List

- **Endpoint**: `POST /statuslists/publish`
- **Description**: Allows an issuer to publish their token status list
- **Authorization**: Requires a valid signed JWT token with the corresponding registered private key with issuer's ID as the `kid` (Key ID) in the header
- **Request Body**

  ```json
  {
    "list_id": "30202cc6-1e3f-4479-a567-74e86ad73693",
    "status": [
      { "index": 1, "status": "INVALID" },
      { "index": 8, "status": "VALID" }
    ]
  }
  ```

  - `index`: Position in the status list
  - `status`: Status value (VALID, INVALID, SUSPENDED, APPLICATIONSPECIFIC)

### Update Status List

- **Endpoint:** `PUT /statuslists/update`
- **Description:** Allows an issuer to update an existing status list
- **Authorization:** Requires a valid signed JWT token with the corresponding registered private key with issuer's ID as the `kid` (Key ID) in the header
- **Request Body:**

  ```json
  {
    "list_id": "755a0cf7-8289-4f65-9d24-0e01be92f4a6",
    "status": [
      {
        "index": 1,
        "status": "VALID"
      },
      {
        "index": 8,
        "status": "INVALID"
      }
    ]
  }
  ```

  - `list_id`: UUID of the status list to update
  - `status`: Array of status updates
    - `index`: Position in the status list
    - `status`: New status value (VALID, INVALID, SUSPENDED, APPLICATIONSPECIFIC)

  Example of a complete status update payload:

  ```json
  {
    "list_id": "755a0cf7-8289-4f65-9d24-0e01be92f4a6",
    "status": [
      {
        "index": 1,
        "status": "VALID"
      },
      {
        "index": 2,
        "status": "INVALID"
      },
      {
        "index": 3,
        "status": "SUSPENDED"
      },
      {
        "index": 4,
        "status": "APPLICATIONSPECIFIC"
      }
    ]
  }
  ```

- **Responses:**
  - `200 OK`: Update successful
  - `400 BAD REQUEST`: Invalid input data
  - `401 UNAUTHORIZED`: Invalid or missing JWT token
  - `403 FORBIDDEN`: Token issuer doesn't match list owner
  - `404 NOT FOUND`: Status list not found
  - `500 INTERNAL SERVER ERROR`: System incurred an error

### Retrieve Status List

- **Endpoint:** `GET /statuslists/{list_id}`
- **Description:** Retrieves the current status list for the requested list_id. This endpoint is publicly accessible with no authentication required.
- **Headers:**
  - `Accept`: Specifies the desired response format
    - `application/jwt`: Returns the status list as a JWT token
    - `application/cwt`: Returns the status list as a CWT token
    - Default: Returns the status list in a compressed and encoded format
- **Responses:**
  - `200 OK`: Returns the status list in the requested format
  - `404 NOT FOUND`: Status list not found
  - `406 NOT ACCEPTABLE`: Requested format not supported

## Authentication

The server uses JWT-based authentication with the following requirements:

1. Issuers must first register their public key using the `/credentials/` endpoint
2. All authenticated requests must include a JWT token in the Authorization header:

   ```http
   Authorization: Bearer <jwt_token>
   ```

3. The JWT token must:
   - Be signed with the algorithm specified during issuer registration.
   - Include the issuer's ID as the `kid` (Key ID) in the header
   - Be signed with the private key corresponding to the registered public key
   - Have valid `exp` (expiration) and `iat` (issued at) claims

Example JWT header:

```json
{
  "alg": "ES256",
  "kid": "issuer-id"
}
```

## Certificate Provisioning and Renewal

The Status List Server is provisioned with a cryptographic certificate that is embedded into all issued status list tokens. This certificate ensures the authenticity and integrity of the tokens distributed by the server.

**Automatic Issuance and Renewal:**

- Certificate issuance and renewal are managed according to the configured renewal strategy.
- Every day at midnight, a cron job checks whether the certificate should be renewed based on this strategy.
- If the certificate is still considered valid according to the configured strategy, no renewal occurs; renewal is only triggered when necessary.

## Error Handling

The server implements proper error handling and returns appropriate HTTP status codes:

- `400 BAD REQUEST`: Invalid input data
- `401 UNAUTHORIZED`: Missing or invalid authentication token
- `403 FORBIDDEN`: Insufficient permissions
- `404 NOT FOUND`: Resource not found
- `500 INTERNAL SERVER ERROR`: Server-side error
