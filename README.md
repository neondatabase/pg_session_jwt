pg\_session\_jwt
================

`pg_session_jwt` is a PostgreSQL extension designed to handle JSON Web Tokens (JWT) within PostgreSQL sessions. It provides utilities to manage JWT-based authentication and user sessions securely in the database.

> [!WARNING]
> This extension is under active development. The entire API is subject to change.

Features
--------

* **Initialize JWT sessions** using a JWKS (JSON Web Key Set).

* **Retrieve the user ID** or session-related information directly from the database.

* Simple JSONB-based storage and retrieval of session information.

Usage
-----

`pg_session_jwt` exposes four main functions:

### 1\. auth.init(kid bigint, jwks jsonb) → void

Initializes a session with a given key identifier (KID) and JWKS data in JSONB format.

### 2\. auth.jwt\_session\_init(jwt text) → void

Initializes the JWT session with the provided `jwt` as a string.

### 3\. auth.get(s text) → jsonb

Retrieves JWT session data as a JSONB object based on the session token.

### 4\. auth.user\_id() → text

Returns the user ID associated with the current session. This is retrieved from the `"sub"` ("subject") field of the JWT.

License
-------
This project is licensed under the Apache License 2.0. See the LICENSE file for details.

Contact
-------
For issues, questions, or support, please open an issue on the GitHub repository.

### Security
Neon adheres to the [securitytxt.org](https://securitytxt.org/) standard for transparent and efficient security reporting. For details on how to report potential vulnerabilities, please visit our [Security reporting](https://neon.tech/docs/security/security-reporting) page or refer to our [security.txt](https://neon.tech/security.txt) file.

If you have any questions about our security protocols or would like a deeper dive into any aspect, our team is here to help. You can reach us at [security@neon](security@neon.tech).tech.