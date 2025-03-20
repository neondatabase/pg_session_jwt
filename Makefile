EXTENSION = pg_session_jwt
DATA = sql/pg_session_jwt--0.0.1--0.1.0.sql sql/pg_session_jwt--0.1.0--0.1.1.sql sql/pg_session_jwt--0.1.1--0.1.2.sql sql/pg_session_jwt--0.1.2--0.2.0.sql

REGRESS = 00_setup 01_basic 02_validation 03_errors
REGRESS_OPTS = --inputdir=regress --outputdir=regress --load-extension=$(EXTENSION)

# Create expected output for setup file
regress/expected/00_setup.out: regress/sql/00_setup.sql
	mkdir -p regress/expected
	echo "-- This file contains the setup for pg_session_jwt tests" > $@
	echo "-- Set the JWK parameter as a GUC parameter before connection start" >> $@
	echo "\set jwk '{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"PLACEHOLDER_KEY\"}'" >> $@
	echo "ALTER SYSTEM SET pg_session_jwt.jwk = :'jwk';" >> $@
	echo "ALTER SYSTEM" >> $@
	echo "SELECT pg_reload_conf();" >> $@
	echo " pg_reload_conf " >> $@
	echo "---------------" >> $@
	echo " t" >> $@
	echo "(1 row)" >> $@
	echo "" >> $@
	echo "CREATE SCHEMA IF NOT EXISTS auth;" >> $@
	echo "CREATE SCHEMA" >> $@
	echo "CREATE EXTENSION pg_session_jwt;" >> $@
	echo "CREATE EXTENSION" >> $@

PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
