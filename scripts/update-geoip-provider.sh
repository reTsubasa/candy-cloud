#!/bin/sh
set -eu

provider_dir=${CANDY_GEOIP_PROVIDER_DIR:-/var/lib/candy/geoip}
countries=${CANDY_GEOIP_COUNTRIES:-CN,US,HK,JP,SG,GB,DE}
base_url=${CANDY_GEOIP_SOURCE_URL:-https://www.ipdeny.com/ipblocks/data/aggregated}
mkdir -p "$provider_dir"
stage=$(mktemp -d "${provider_dir}.stage.XXXXXX")
trap 'rm -rf "$stage"' EXIT INT TERM
old_ifs=$IFS
IFS=,
for country in $countries; do
  code=$(printf '%s' "$country" | tr '[:upper:]' '[:lower:]')
  case "$code" in
    [a-z][a-z]) ;;
    *) echo "invalid GeoIP country code: $country" >&2; exit 1 ;;
  esac
  output="$stage/${code}-ip.cidr"
  if ! wget -q --https-only --secure-protocol=TLSv1_2 --timeout=30 --tries=4 \
      -O "$output" "$base_url/${code}-aggregated.zone"; then
    if [ -s "$provider_dir/${code}-ip.cidr" ]; then
      cp "$provider_dir/${code}-ip.cidr" "$output"
      echo "GeoIP refresh failed for ${code}; retained the previous verified provider" >&2
    else
      echo "GeoIP provider unavailable for ${code} and no previous copy exists" >&2
      exit 1
    fi
  fi
  awk '
    BEGIN { valid = 1; count = 0 }
    /^[[:space:]]*($|#)/ { next }
    /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\/(3[0-2]|[12]?[0-9])$/ { count++; next }
    { valid = 0 }
    END { if (!valid || count == 0) exit 1 }
  ' "$output" || { echo "invalid or empty GeoIP provider for ${code}" >&2; exit 1; }
done
IFS=$old_ifs

date -u +%Y-%m-%d > "$stage/VERSION"
for file in "$stage"/*-ip.cidr; do
  install -m 0444 "$file" "$provider_dir/$(basename "$file").new"
done
install -m 0444 "$stage/VERSION" "$provider_dir/VERSION.new"
for file in "$provider_dir"/*.new; do
  mv "$file" "${file%.new}"
done
echo "GeoIP provider refreshed: countries=$countries version=$(cat "$provider_dir/VERSION")"
