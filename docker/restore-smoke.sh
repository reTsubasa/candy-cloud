#!/bin/sh
set -eu
test -n "${BACKUP_FILE:-}" || { echo 'BACKUP_FILE is required' >&2; exit 2; }
test -f "$BACKUP_FILE" || { echo "backup not found: $BACKUP_FILE" >&2; exit 2; }
docker compose exec -T mysql sh -c 'exec mysql -uroot -p"$MYSQL_ROOT_PASSWORD" "$MYSQL_DATABASE"' < "$BACKUP_FILE"
