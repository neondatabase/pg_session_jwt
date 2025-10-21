-- Downgrade from 0.4.0 to 0.3.1
-- Drop the SQL functions added in 0.4.0

DROP FUNCTION IF EXISTS auth.jwt();
DROP FUNCTION IF EXISTS auth.uid();

