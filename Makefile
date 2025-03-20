EXTENSION = pg_session_jwt
DATA = sql/pg_session_jwt--0.0.1--0.1.0.sql sql/pg_session_jwt--0.1.0--0.1.1.sql sql/pg_session_jwt--0.1.1--0.1.2.sql sql/pg_session_jwt--0.1.2--0.2.0.sql

REGRESS = 01_basic 02_validation 03_errors
REGRESS_OPTS = --inputdir=regress --outputdir=regress --load-extension=$(EXTENSION)

PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
