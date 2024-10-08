pg\_session\_jwt
================

`pg_session_jwt` is a PostgreSQL extension designed to handle authenticated sessions through a JWT. This JWT is then verified against a JWK (JSON Web Key) to ensure its authenticity. Both the JWK and the JWT must be provided to the extension by a Postgres superuser. The extension then stores the JWT in the database for later retrieval, and exposes functions to retrieve the user ID (the `sub` subject field) and other parts of the payload.

The goal of this extension is to provide a secure and efficient way to manage authenticated sessions in a PostgreSQL database. The JWTs can be generated by third-party auth providers, and then developers can leverage the JWT for [Row Level Security](https://www.postgresql.org/docs/current/ddl-rowsecurity.html) (RLS) policies, or to retrieve the user ID for other purposes (column defaults, filters, etc.).

> [!WARNING]
> This extension is under active development. The entire API is subject to change.

Features
--------

* **Initialize JWT sessions** using a JWK (JSON Web Key).

* **Retrieve the user ID** or other session-related information directly from the database.

* Simple JSONB-based storage and retrieval of session information.

Usage
-----

`pg_session_jwt` exposes four main functions:

### 1\. auth.init(kid bigint, jwk jsonb) → void

Initializes a session with a given key identifier (KID) and JWK data in JSONB format.

### 2\. auth.jwt\_session\_init(jwt text) → void

Initializes the JWT session with the provided `jwt` as a string.

### 3\. auth.session(s text) → jsonb

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

If you have any questions about our security protocols or would like a deeper dive into any aspect, our team is here to help. You can reach us at [security@neon.tech](security@neon.tech).
