#!/usr/bin/env sh
set -eu

die() {
  printf '%s\n' "$*" >&2
  exit 64
}

yaml_quote() {
  value=$(printf '%s' "$1" | sed "s/'/''/g")
  printf "'%s'" "$value"
}

append_scalar() {
  key=$1
  value=$2
  {
    printf '%s: ' "$key"
    yaml_quote "$value"
    printf '\n'
  } >> "$runtime_config"
}

append_bool() {
  key=$1
  value=$2
  case "$value" in
    true|false) printf '%s: %s\n' "$key" "$value" >> "$runtime_config" ;;
    TRUE|True) printf '%s: true\n' "$key" >> "$runtime_config" ;;
    FALSE|False) printf '%s: false\n' "$key" >> "$runtime_config" ;;
    *) die "$key must be true or false, got: $value" ;;
  esac
}

append_list() {
  key=$1
  value=$2
  normalized=$(printf '%s' "$value" | tr ',' ' ')

  [ -n "$normalized" ] || return 0

  printf '%s:\n' "$key" >> "$runtime_config"
  for item in $normalized; do
    {
      printf '  - '
      yaml_quote "$item"
      printf '\n'
    } >> "$runtime_config"
  done
}

reject_service_account_args() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --credentials|-c|--subjectemail|--config)
        die "This image is access-token only. Do not pass $1; use SCUBAGOGGLES_ACCESS_TOKEN and SCUBAGOGGLES_CONFIG."
        ;;
      --credentials=*|--subjectemail=*|--config=*)
        die "This image is access-token only. Do not pass ${1%%=*}; use SCUBAGOGGLES_ACCESS_TOKEN and SCUBAGOGGLES_CONFIG."
        ;;
    esac
    shift
  done
}

case "${1:-}" in
  sh|bash|python|scubagoggles)
    exec "$@"
    ;;
  getopa|purge|setup|version)
    exec scubagoggles "$@"
    ;;
  gws)
    shift
    ;;
esac

reject_service_account_args "$@"

[ -z "${GOOGLE_APPLICATION_CREDENTIALS:-}" ] \
  || die "GOOGLE_APPLICATION_CREDENTIALS is set, but this image is access-token only."
[ -z "${SCUBAGOGGLES_CREDENTIALS:-}" ] \
  || die "SCUBAGOGGLES_CREDENTIALS is set, but this image is access-token only."
[ -z "${SCUBAGOGGLES_SUBJECT_EMAIL:-}" ] \
  || die "SCUBAGOGGLES_SUBJECT_EMAIL is set, but this image is access-token only."

access_token=${SCUBAGOGGLES_ACCESS_TOKEN:-${ACCESS_TOKEN:-}}
mounted_config=${SCUBAGOGGLES_CONFIG:-}

[ -n "$access_token" ] || [ -n "$mounted_config" ] \
  || die "Set SCUBAGOGGLES_ACCESS_TOKEN, ACCESS_TOKEN, or SCUBAGOGGLES_CONFIG containing accesstoken."

output_path=${SCUBAGOGGLES_OUTPUT_PATH:-/output}
opa_dir=${SCUBAGOGGLES_OPA_DIR:-/opt/opa}
customer_id=${SCUBAGOGGLES_CUSTOMER_ID:-my_customer}
quiet=${SCUBAGOGGLES_QUIET:-true}

runtime_dir=${SCUBAGOGGLES_RUNTIME_DIR:-/tmp/scubagoggles-runtime}
runtime_config="$runtime_dir/config.yaml"

mkdir -p "$runtime_dir" "$output_path"
: > "$runtime_config"
chmod 0600 "$runtime_config"

if [ -n "$mounted_config" ]; then
  [ -f "$mounted_config" ] || die "SCUBAGOGGLES_CONFIG does not exist: $mounted_config"
  if grep -Eq '^[[:space:]]*(credentials|subjectemail)[[:space:]]*:' "$mounted_config"; then
    die "SCUBAGOGGLES_CONFIG must not contain credentials or subjectemail; this image is access-token only."
  fi
  if [ -z "$access_token" ] && ! grep -Eq '^[[:space:]]*accesstoken[[:space:]]*:' "$mounted_config"; then
    die "SCUBAGOGGLES_CONFIG must contain accesstoken when SCUBAGOGGLES_ACCESS_TOKEN is not set."
  fi
  cat "$mounted_config" >> "$runtime_config"
  printf '\n' >> "$runtime_config"
fi

[ -z "$access_token" ] || append_scalar "accesstoken" "$access_token"
append_scalar "outputpath" "$output_path"
append_scalar "opapath" "$opa_dir"
append_scalar "customerid" "$customer_id"
append_bool "quiet" "$quiet"

[ -z "${SCUBAGOGGLES_BASELINES:-}" ] || append_list "baselines" "$SCUBAGOGGLES_BASELINES"
[ -z "${SCUBAGOGGLES_ORG_NAME:-}" ] || append_scalar "orgname" "$SCUBAGOGGLES_ORG_NAME"
[ -z "${SCUBAGOGGLES_ORG_UNIT_NAME:-}" ] || append_scalar "orgunitname" "$SCUBAGOGGLES_ORG_UNIT_NAME"

exec scubagoggles gws --config "$runtime_config" "$@"
