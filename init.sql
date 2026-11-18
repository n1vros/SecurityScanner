-- STOscanner database bootstrap (mounted by docker-compose.yml).
-- The application creates its own tables at startup; this only prepares
-- extensions and defaults that require superuser privileges.

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS pgcrypto;

ALTER DATABASE stoscanner SET timezone TO 'UTC';
