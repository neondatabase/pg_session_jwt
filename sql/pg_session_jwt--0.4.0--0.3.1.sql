-- removes alias function auth.uid() for auth.user_id()
DROP FUNCTION IF EXISTS auth.uid();
