-- adds alias function auth.uid() for auth.user_id()
CREATE FUNCTION auth."uid"() RETURNS TEXT
STRICT STABLE PARALLEL SAFE
LANGUAGE c
AS 'MODULE_PATHNAME', 'uid_wrapper';

-- adds alias function auth.jwt() for auth.session()
CREATE FUNCTION auth."jwt"() RETURNS jsonb
STRICT STABLE PARALLEL SAFE
LANGUAGE c
AS 'MODULE_PATHNAME', 'jwt_wrapper';
