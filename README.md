# Status List Server

The Status List Server is a web service that manages and publishes status lists, allowing issuers to update statuses and verifiers to retrieve them. It implements JWT-based authentication using ES256 (ECDSA with P-256 and SHA-256) for securing its endpoints.

## Prerequisites
Before setting up the Status List Server, ensure you have the following installed:

- [Rust](https://www.rust-lang.org/tools/install): The programming language used to develop the server.
- [Cargo](https://doc.rust-lang.org/cargo/getting-started/installation.html): The Rust package manager.
- [PostgreSQL](https://www.postgresql.org/download/): The database system used for storing status lists.

## Installation

**Clone the Repository:**

   ```bash
    git clone https://github.com/adorsys/status-list-server.git
    cd status-list-server
   ```

## Running with Docker Compose
You can run the project directly using docker compose:

- Execute the command below at the root of the project
```sh
docker-compose up
```
This command will pull and start postgres and also build the project image and start a container.

## Configuration

 **Environment Variables:**

   Create a `.env` file in the root directory with the following configurations:

   ```env
   DATABASE_URL=postgres://username:password@localhost/status_list_db
   ```

   Replace `username` and `password` with your PostgreSQL credentials.

## Running the Server

To start the server, execute:

```bash
cargo run
```

By default, the server runs on `http://localhost:8000`. You can modify the port in the configuration settings.

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
    "public_key": "<public_key.pem>",
    "alg": "ES256"
  }
  ```
  - `issuer`: Unique identifier for the issuer
  - `public_key`: PEM-encoded public key in base64 format
  - `alg`: "ES256" (ECDSA with P-256 and SHA-256)
 
### Publish Status List
- **Endpoint**: `POST /statuslists/publish` 
- **Description**: Allows an issuer to publish their token status list
- **Authorization**: Requires a valid signed JWT token with the corresponding registered private key with issuer's ID as the `kid` (Key ID) in the header
- **Request Body**
  ```json
  { "list_id": "30202cc6-1e3f-4479-a567-74e86ad73693",
  [
      { "index": 1, "status": "INVALID" },
      { "index": 8, "status": "VALID" }
  ]
  }
  ```
  - `index`: Position in the status list
  - `status`: Status value (VALID, INVALID, SUSPENDED, APPLICATIONSPECIFIC)

### Update Status List

- **Endpoint:** `PUT /statuslists/{list_id}`
- **Description:** Allows an issuer to update an existing status list
- **Authorization:** Requires a valid signed JWT token with the corresponding registered private key with issuer's ID as the `kid` (Key ID) in the header
  
- **Request Body:** 

  ```json
  {
    "list_id": "755a0cf7-8289-4f65-9d24-0e01be92f4a6",
    "updates": [
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
  - `updates`: Array of status updates
    - `index`: Position in the status list
    - `status`: New status value (VALID, INVALID, SUSPENDED, APPLICATIONSPECIFIC)

  Example of a complete status update payload:
  ```json
  {
    "list_id": "755a0cf7-8289-4f65-9d24-0e01be92f4a6",
    "updates": [
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
   ```
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
## Error Handling
The server implements proper error handling and returns appropriate HTTP status codes:
- `400 BAD REQUEST`: Invalid input data
- `401 UNAUTHORIZED`: Missing or invalid authentication token
- `403 FORBIDDEN`: Insufficient permissions
- `404 NOT FOUND`: Resource not found
- `500 INTERNAL SERVER ERROR`: Server-side error