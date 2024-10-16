-- src/lib.rs:265
-- pg_session_jwt::auth::session
CREATE OR REPLACE FUNCTION auth."session"() RETURNS jsonb /* pgrx::datum::json::JsonB */
STRICT LANGUAGE c /* Rust */
AS 'MODULE_PATHNAME', 'session_wrapper';

-- src/lib.rs:195
-- pg_session_jwt::auth::jwt_session_init
DROP FUNCTION auth."jwt_session_init"(text);
CREATE OR REPLACE FUNCTION auth."jwt_session_init"("jwt" TEXT) RETURNS void
STRICT LANGUAGE c /* Rust */
AS 'MODULE_PATHNAME', 'jwt_session_init_wrapper';

-- src/lib.rs:57
-- pg_session_jwt::auth::init
CREATE OR REPLACE FUNCTION auth."init"() RETURNS void
STRICT LANGUAGE c /* Rust */
AS 'MODULE_PATHNAME', 'init_wrapper';
