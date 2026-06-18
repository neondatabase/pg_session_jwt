-- This file contains the setup for pg_session_jwt tests
-- Set the JWK parameter as a GUC parameter before connection start
\set jwk '{"kty":"OKP","crv":"Ed25519","x":"PLACEHOLDER_KEY"}'
ALTER SYSTEM SET pg_session_jwt.jwk = :'jwk';
SELECT pg_reload_conf();

CREATE SCHEMA IF NOT EXISTS auth;
CREATE EXTENSION pg_session_jwt;
