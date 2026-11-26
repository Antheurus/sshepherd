-- Fixture data + the read-only role sshepherd's docs recommend (targets.example.toml,
-- references/db.md layer 1). Runs once, on first boot of the postgres fixture container.

CREATE ROLE sshepherd_ro WITH LOGIN;
GRANT pg_read_all_data TO sshepherd_ro;
ALTER ROLE sshepherd_ro SET default_transaction_read_only = on;

CREATE TABLE IF NOT EXISTS smoke_fixture (
  id serial PRIMARY KEY,
  note text NOT NULL
);

INSERT INTO smoke_fixture (note) VALUES ('hello from sshepherd smoke fixture');

-- db query's row limit: more rows than DB_QUERY_ROW_LIMIT (500).
CREATE TABLE big (id integer PRIMARY KEY, label text NOT NULL);
INSERT INTO big (id, label) SELECT n, 'row ' || n FROM generate_series(1, 1200) AS n;

-- db describe / db count: columns with defaults and nulls, an index and a foreign key.
CREATE TABLE orgs (id serial PRIMARY KEY, name text NOT NULL);
CREATE TABLE users (
  id serial PRIMARY KEY,
  email text NOT NULL UNIQUE,
  org_id integer REFERENCES orgs (id),
  created_at timestamptz NOT NULL DEFAULT now(),
  nickname text
);
CREATE INDEX users_org_id_idx ON users (org_id);
INSERT INTO orgs (name) VALUES ('Acme Logistics');
INSERT INTO users (email, org_id, nickname) VALUES
  ('rina@example.com', 1, 'rina'),
  ('budi@example.com', 1, NULL);

-- db migrations: a prisma history and a rails one.
CREATE TABLE _prisma_migrations (
  id varchar(36) PRIMARY KEY,
  checksum varchar(64) NOT NULL,
  finished_at timestamptz,
  migration_name varchar(255) NOT NULL,
  logs text,
  rolled_back_at timestamptz,
  started_at timestamptz NOT NULL DEFAULT now(),
  applied_steps_count integer NOT NULL DEFAULT 0
);
INSERT INTO _prisma_migrations (id, checksum, finished_at, migration_name, started_at, applied_steps_count) VALUES
  ('0d6b3c1e-0000-4000-8000-000000000001', 'c1', '2026-10-01 09:00:00+00', '20261001090000_init', '2026-10-01 09:00:00+00', 1),
  ('0d6b3c1e-0000-4000-8000-000000000002', 'c2', '2026-11-02 10:30:00+00', '20261102103000_add_users_nickname', '2026-11-02 10:30:00+00', 1);
CREATE TABLE schema_migrations (version varchar PRIMARY KEY);
INSERT INTO schema_migrations (version) VALUES ('20260901000000'), ('20261015000000');
