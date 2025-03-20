-- Error case tests for pg_session_jwt

-- Set required parameters
-- This is a placeholder value that should be replaced with a real JWK at test time
SET pg_session_jwt.jwk = '{"kty":"OKP","crv":"Ed25519","x":"PLACEHOLDER_KEY"}';
SELECT auth.init();

-- Test error: decreasing token ID
DO $$
DECLARE
    -- These are placeholder values that should be replaced with real JWTs at test time
    test_jwt1 TEXT := 'PLACEHOLDER.JWT.VALUE_JTI2';
    test_jwt2 TEXT := 'PLACEHOLDER.JWT.VALUE_JTI1';
BEGIN
    PERFORM auth.jwt_session_init(test_jwt1);
    BEGIN
        PERFORM auth.jwt_session_init(test_jwt2);
        RAISE EXCEPTION 'Expected error did not occur';
    EXCEPTION
        WHEN check_violation THEN
            RAISE NOTICE 'Expected error caught: Token ID must be strictly monotonically increasing';
    END;
END;
$$;
