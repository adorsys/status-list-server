# Status List Server

The Status List Server is a web service that manages and publishes status lists, allowing issuers to update statuses and verifiers to retrieve them. It implements the OAuth 2.0 Authorization Framework to secure its endpoints.

## Prerequisites
Before setting up the Status List Server, ensure you have the following installed:

- [Rust](https://www.rust-lang.org/tools/install): The programming language used to develop the server.
- [Cargo](https://doc.rust-lang.org/cargo/getting-started/installation.html): The Rust package manager.
- [PostgreSQL](https://www.postgresql.org/download/): The database system used for storing status lists.

## Installation

**Clone the Repository:**

   ```bash
    https://github.com/adorsys/status-list-server.git
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
  
### Publish Credentials
- **Endpoint**: `POST /credentials/`
- **Description**: allow issuers to publish their credentials (`public_key`) and identifiers used to later for authorisation verification
- **Request Body**
  ```json
  {"issuer": "<value>", "public_key": "<public_key>", "alg": "<alg>"}
  ```
 
### Publish statuslist
- **Endpoint**: `POST /statuslist/{issuer}` 
- **Description**: Allows an issuer to publish his token status from which will be created a status list
- **Authorization**: Requires a valid sign jwt with the issuer scope (a signed jwt with issuers as kid).
- **Request Body**
  ```json
  [
      { "index": 1, "status": "INVALID" },
      { "index": 8, "status": "VALID" }
    ]
  ```

### Update Status List

- **Endpoint:** `PUT /statuslist/{issuer}`
- **Description:** Allows an issuer to update the status list.
- **Authorization:** Requires a valid sign jwt with the issuer scope (a signed jwt with issuers as kid).
  
- **Request Body:** 

  ```json
  {
    "updates": [
      { "index": 1, "status": "VALID" },
      { "index": 8, "status": "INVALID" }
    ]
  }
  ```
  
  - `index`: The position in the status list to update.
  - `status`: The new status value. Possible values: `VALID`, `INVALID`, `SUSPENDED`, `APPLICATIONSPECIFIC`.
  

- **Responses:**
  - `202 ACCEPTED`: The update request has been accepted and processed.
  - `400 BAD REQUEST`: Invalid input data.
  - `401 UNAUTHORIZED`: Missing or invalid authentication token.
  - `403 FORBIDDEN`: Insufficient permissions.

### Retrieve Status List

- **Endpoint:** `GET /statuslist/{issuer}`
- **Description:** Retrieves the current status list for the specified issuer.
- **Responses:**
  - `200 OK`: Returns the status list in a compressed and encoded format.
  - `401 UNAUTHORIZED`: Missing or invalid authentication token.
  - `403 FORBIDDEN`: Insufficient permissions.
  - `404 NOT FOUND`: Issuer not found.


### Issuer Authorization
The issuer should construct and sign a sample jwt with issuer as kid which will be used to get the key to verify the jwt 

Ensure that the database is set up and the necessary environment variables are configured before running tests.
