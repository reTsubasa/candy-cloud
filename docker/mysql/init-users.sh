#!/bin/bash
set -euo pipefail
case "$MYSQL_DATABASE" in
  ""|*[!A-Za-z0-9_]*)
    echo "init-users: MYSQL_DATABASE must contain only letters, numbers, and underscores" >&2
    exit 1
    ;;
esac

mysql_command=(mysql -uroot -p"$MYSQL_ROOT_PASSWORD")
if [[ -n "${MYSQL_HOST:-}" ]]; then
  mysql_command+=(-h "$MYSQL_HOST")
fi

"${mysql_command[@]}" <<SQL
CREATE USER IF NOT EXISTS 'cloud_migrator'@'%' IDENTIFIED BY '${MYSQL_MIGRATOR_PASSWORD}';
CREATE USER IF NOT EXISTS 'cloud_api'@'%' IDENTIFIED BY '${MYSQL_API_PASSWORD}';
CREATE USER IF NOT EXISTS 'cloud_identity'@'%' IDENTIFIED BY '${MYSQL_IDENTITY_PASSWORD}';
CREATE USER IF NOT EXISTS 'cloud_auth'@'%' IDENTIFIED BY '${MYSQL_AUTH_PASSWORD}';
CREATE USER IF NOT EXISTS 'cloud_worker'@'%' IDENTIFIED BY '${MYSQL_WORKER_PASSWORD}';
GRANT ALL PRIVILEGES ON \`${MYSQL_DATABASE}\`.* TO 'cloud_migrator'@'%';
GRANT SELECT, INSERT, UPDATE, DELETE ON \`${MYSQL_DATABASE}\`.* TO 'cloud_api'@'%';
GRANT SELECT, INSERT, UPDATE, DELETE ON \`${MYSQL_DATABASE}\`.* TO 'cloud_identity'@'%';
GRANT SELECT, INSERT, UPDATE ON \`${MYSQL_DATABASE}\`.* TO 'cloud_auth'@'%';
GRANT SELECT, INSERT, UPDATE ON \`${MYSQL_DATABASE}\`.* TO 'cloud_worker'@'%';
FLUSH PRIVILEGES;
SQL

# MySQL runs entrypoint scripts before application migrations, and table-level
# grants require the table to exist. Post-migration reconciliation invokes this
# same script again and reaches this least-privilege grant.
table_exists=$("${mysql_command[@]}" --batch --skip-column-names <<SQL
SELECT COUNT(*) FROM information_schema.tables
WHERE table_schema = '${MYSQL_DATABASE}'
  AND table_name = 'runtime_projection_transport_catalog';
SQL
)
if [[ "$table_exists" == 1 ]]; then
  "${mysql_command[@]}" <<SQL
GRANT DELETE ON \`${MYSQL_DATABASE}\`.\`runtime_projection_transport_catalog\` TO 'cloud_auth'@'%';
SQL
fi
