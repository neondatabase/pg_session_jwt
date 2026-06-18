-- Validation tests for pg_session_jwt

-- Initialize the session
SELECT auth.init();

-- Test JWT token ID (jti) monotonically increasing
DO $$
DECLARE
    -- These are placeholder values that should be replaced with real JWTs at test time
    test_jwt1 TEXT := 'PLACEHOLDER.JWT.VALUE1';
    test_jwt2 TEXT := 'PLACEHOLDER.JWT.VALUE2';
BEGIN
    PERFORM auth.jwt_session_init(test_jwt1);
    PERFORM auth.jwt_session_init(test_jwt2);
END;
$$;

-- Test JWT payload retrieval
SELECT jsonb_typeof(auth.session()) AS session_type;
SELECT auth.user_id() AS user_id;
