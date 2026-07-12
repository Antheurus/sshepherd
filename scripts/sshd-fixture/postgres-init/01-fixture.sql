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
