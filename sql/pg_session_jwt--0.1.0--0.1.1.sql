-- src/lib.rs:284
-- pg_session_jwt::auth::user_id
CREATE OR REPLACE FUNCTION auth."user_id"() RETURNS TEXT /* core::option::Option<alloc::string::String> */
STRICT STABLE PARALLEL SAFE
LANGUAGE c /* Rust */
AS 'MODULE_PATHNAME', 'user_id_wrapper';

-- src/lib.rs:265
-- pg_session_jwt::auth::session
CREATE OR REPLACE FUNCTION auth."session"() RETURNS jsonb /* pgrx::datum::json::JsonB */
STRICT STABLE PARALLEL SAFE
LANGUAGE c /* Rust */
AS 'MODULE_PATHNAME', 'session_wrapper';
