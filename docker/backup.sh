#!/bin/sh
set -eu
: "${MYSQL_ROOT_PASSWORD:?MYSQL_ROOT_PASSWORD is required}"
out_dir=${BACKUP_DIR:-./backups}
mkdir -p "$out_dir"
chmod 700 "$out_dir"
file="$out_dir/candy-cloud-$(date -u +%Y%m%dT%H%M%SZ).sql"
docker compose exec -T mysql sh -c 'exec mysqldump -uroot -p"$MYSQL_ROOT_PASSWORD" --single-transaction --routines --events "$MYSQL_DATABASE"' > "$file"
chmod 600 "$file"
echo "$file"
