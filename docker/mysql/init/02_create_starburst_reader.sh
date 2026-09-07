#!/bin/bash
# Create the dedicated read-only account used by the AIDP/Starburst MySQL catalog.
#
# This lives in a shell script rather than a .sql file because the MySQL
# entrypoint does not template variables into .sql files - doing it here keeps
# the password in the container environment only, never in a file or in Git.
#
# The account gets SELECT on customer360 and nothing else: no write privileges,
# no administrative privileges, and no access to any other schema. AIDP must
# never use the root account.
set -euo pipefail

: "${MYSQL_STARBURST_USER:?MYSQL_STARBURST_USER is required}"
: "${MYSQL_STARBURST_PASSWORD:?MYSQL_STARBURST_PASSWORD is required}"
DB="${MYSQL_DATABASE:-customer360}"

echo "[init] Creating read-only Starburst user '${MYSQL_STARBURST_USER}' on '${DB}'"

# --password is read from stdin-free env by the client below; the heredoc keeps
# the password out of the process argument list.
mysql --protocol=socket -uroot -p"${MYSQL_ROOT_PASSWORD}" <<SQL
-- '%' rather than 'localhost': AIDP worker nodes connect from off-host, so a
-- localhost-only grant is the single most common cause of "Access denied".
CREATE USER IF NOT EXISTS '${MYSQL_STARBURST_USER}'@'%'
    IDENTIFIED WITH mysql_native_password BY '${MYSQL_STARBURST_PASSWORD}';

ALTER USER '${MYSQL_STARBURST_USER}'@'%'
    IDENTIFIED WITH mysql_native_password BY '${MYSQL_STARBURST_PASSWORD}';

-- Read-only by design. SELECT is all the Trino MySQL connector needs for
-- metadata discovery and reads; no INSERT/UPDATE/DELETE/CREATE/DROP, no GRANT
-- OPTION, no global privileges.
REVOKE ALL PRIVILEGES, GRANT OPTION FROM '${MYSQL_STARBURST_USER}'@'%';
GRANT SELECT ON \`${DB}\`.* TO '${MYSQL_STARBURST_USER}'@'%';

FLUSH PRIVILEGES;
SQL

echo "[init] Read-only Starburst user ready (SELECT on ${DB} only)"
