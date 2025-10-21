-- Add auth.jwt() and auth.uid() SQL functions
-- These are simple SQL stored procedures that read JWT claims from GUC settings

-- Returns the full JWT claims as jsonb
-- Checks both request.jwt.claim and request.jwt.claims for compatibility
CREATE OR REPLACE FUNCTION auth.jwt()
RETURNS jsonb
LANGUAGE sql STABLE
AS $$
  SELECT 
    coalesce(
        nullif(current_setting('request.jwt.claim', true), ''),
        nullif(current_setting('request.jwt.claims', true), '')
    )::jsonb
$$;

-- Returns the sub (subject) claim as a UUID
-- Checks both request.jwt.claim.sub and extracts sub from request.jwt.claims
CREATE OR REPLACE FUNCTION auth.uid() 
RETURNS uuid 
LANGUAGE sql STABLE
AS $$
  SELECT 
  coalesce(
    nullif(current_setting('request.jwt.claim.sub', true), ''),
    (nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'sub')
  )::uuid
$$;

