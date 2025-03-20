-- Basic functionality tests for pg_session_jwt

-- Set required parameters
-- Note: In real tests, we'll need to set pg_session_jwt.jwk to a valid JWK
-- This is a placeholder value that should be replaced with a real JWK at test time
SET pg_session_jwt.jwk = '{"kty":"OKP","crv":"Ed25519","x":"PLACEHOLDER_KEY"}';

-- Test auth.init() function
SELECT auth.init();

-- Test creating a session with a valid JWT
-- In real tests, we would use a function to generate a valid JWT
DO $$
DECLARE
    -- This is a placeholder value that should be replaced with a real JWT at test time
    test_jwt TEXT := 'PLACEHOLDER.JWT.VALUE';
BEGIN
    PERFORM auth.jwt_session_init(test_jwt);
END;
$$;

-- Test auth.session() function
SELECT auth.session() IS NOT NULL AS session_exists;

-- Test auth.user_id() function
SELECT auth.user_id() AS user_id;
