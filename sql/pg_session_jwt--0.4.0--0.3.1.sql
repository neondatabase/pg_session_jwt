-- removes alias function auth.uid() for auth.user_id()
DROP FUNCTION IF EXISTS auth.uid();

-- removes alias function auth.jwt() for auth.session()
DROP FUNCTION IF EXISTS auth.jwt();
