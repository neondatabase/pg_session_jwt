-- adds auth.organization() and auth.organization_id() for Neon Auth organization plugin
CREATE OR REPLACE FUNCTION auth."organization"() RETURNS jsonb
STABLE PARALLEL SAFE
LANGUAGE c
AS 'MODULE_PATHNAME', 'organization_wrapper';

CREATE OR REPLACE FUNCTION auth."organization_id"() RETURNS uuid
STABLE PARALLEL SAFE
LANGUAGE c
AS 'MODULE_PATHNAME', 'organization_id_wrapper';
