## **Status List Server: Developer Guide and Architecture Documentation**

### **1. Introduction**
   - **Purpose**: The Status List Server is a service that provides **Status List Tokens** to Relying Parties for verifying the status of Referenced Tokens (e.g., OAuth 2.0 tokens). It enables efficient and scalable token status management.
   - **Key Features**:
     - Serve Status List Tokens in JWT or CWT format.
     - Support for high-frequency status updates.
     - Scalable and secure architecture.
   - **Audience**: This guide is intended for developers integrating with the Status List Server, including Relying Parties and Token Issuers.
  
### **2. Architecture Overview**
   - **High-Level Diagram**:
  
![x](./arc.png)

   - **Components**:
     1. **Token Issuer**: Issues Referenced Tokens with a `status` claim pointing to the Status List Server.
     2. **Status List Server**: Hosts and serves Status List Tokens containing token statuses.
     3. **Relying Party**: Requests and uses Status List Tokens to verify the status of Referenced Tokens.

### **3. Workflows**
   - **Token Issuance**:
     1. The **Token Issuer** creates a Referenced Token with a `status` claim containing:
        - `status_list.url`: The URL of the Status List Server.
        - `status_list.index`: The index of the token's status in the Status List Token.
     2. The Referenced Token is sent to the client.

   - **Status List Token Retrieval**:
     1. The **Relying Party** extracts the `status` claim from the Referenced Token.
     2. It sends an HTTP GET request to the `status_list.url` with an `Accept` header (`application/statuslist+jwt` or `application/statuslist+cwt`).
     3. The **Status List Server** responds with the Status List Token in the requested format.

   - **Token Status Verification**:
     1. The **Relying Party** decodes the Status List Token (JWT or CWT).
     2. It uses the `status_list.index` to locate the token's status in the Status List Token.
     3. The status is used to determine if the Referenced Token is valid, revoked, or expired.



### **4. API Specifications**
  **Endpoints**:
   -  ` GET /statuslists/{id}`
   - **Request Headers**:
     - `Accept`: `application/statuslist+jwt` or `application/statuslist+cwt`.
   - **Response**:
     - **Status Code**: `200 OK` (success) or `3xx` (redirect).
     - **Headers**:
       - `Content-Type`: `application/statuslist+jwt` or `application/statuslist+cwt`.
       - `Content-Encoding`: `gzip` (optional, for compression).
     - **Body**: The Status List Token in JWT or CWT format.
   - `GET /statelists/{status_list_id}`
   - **Request Headers**:
     - `Accept`: `application/statuslist+jwt` or `application/statuslist+cwt`.
   - **Response**:
     - **Status Code**: `200 OK` (success) or `3xx` (redirect).
     - **Headers**:
       - `Content-Type`: `application/statuslist+jwt` or `application/statuslist+cwt`.
     Example Response Body (JWT): 
     `eyJhbGciOiJFUzI1NiIsImtpZCI6IjEyIiwidHlwIjoic3RhdHVzbGlzdCtqd3QifQ...`
  
### **5. Data Formats**
   - **Referenced Token**:
     ```json
     {
       "iss": "https://issuer.example.com",
       "sub": "user123",
       "status": {
         "status_list": {
           "url": "https://statuslist.example.com/statuslists/1",
           "index": 42
         }
       }
     }
     ```

   - **Status List Token (JWT Example)**:
     ```json
     {
       "iss": "https://statuslist.example.com",
       "sub": "https://issuer.example.com",
       "status_list": {
         "bits": 1,
         "lst": "eyJhbGciOiJFUzI1NiIsImtpZCI6IjEyIiwidHlwIjoic3RhdHVzbGlzdCtqd3QifQ..."
       },
       "exp": 2291720170,
       "ttl": 43200
     }
     ```

### **6. Security Considerations**
   - **HTTPS**: All communication with the Status List Server must use HTTPS to ensure data integrity and confidentiality.
   - **Token Signing**: Status List Tokens must be signed (e.g., using JWT or CWT) to prevent tampering.
   - **CORS**: The Status List Server should support Cross-Origin Resource Sharing (CORS) for browser-based clients.
   - **Rate Limiting**: Implement rate limiting to prevent abuse of the Status List Server.

### **7. Deployment and Scalability**
   - **Hosting**: The Status List Server can be hosted on cloud platforms (e.g., AWS, Azure, GCP) for scalability.
   - **Caching**: Use HTTP caching headers (`Cache-Control`, `Expires`) or rely on the `exp` and `ttl` claims in the Status List Token for caching.
   - **Load Balancing**: Use load balancers to distribute traffic across multiple instances of the Status List Server.

### **8. Developer Integration**
   - **Step 1**: Configure the Token Issuer to include the `status` claim in Referenced Tokens.
   - **Step 2**: Implement the Relying Party to:
     1. Extract the `status` claim from the Referenced Token.
     2. Request the Status List Token from the Status List Server.
     3. Decode and verify the Status List Token.
     4. Use the `index` to check the token's status.
   - **Step 3**: Test the integration using sample Referenced Tokens and Status List Tokens.

### **9. References**
   - [IETF Draft: OAuth Status List](https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/)
   - [JWT (JSON Web Token) RFC 7519](https://tools.ietf.org/html/rfc7519)
   - [CWT (CBOR Web Token) RFC 8392](https://tools.ietf.org/html/rfc8392)
