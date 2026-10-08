#!/usr/bin/env sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

normalize_opa_arch() {
  case "$1" in
    amd64|x86_64) printf 'amd64' ;;
    arm64|aarch64) printf 'arm64' ;;
    *)
      printf 'Unsupported OPA architecture: %s
' "$1" >&2
      exit 65
      ;;
  esac
}

source_dir=${SCUBAGOGGLES_SOURCE:-/path/to/ScubaGoggles}
image_tag=${IMAGE_TAG:-scubagoggles-access-token:local}
context_dir=${SCUBAGOGGLES_DOCKER_CONTEXT:-$script_dir/.build/context}
opa_version=${OPA_VERSION:-v1.17.1}
opa_binary=${OPA_BINARY:-}
docker_platform=${DOCKER_PLATFORM:-${DOCKER_DEFAULT_PLATFORM:-}}

if [ -n "${OPA_ARCH:-}" ]; then
  opa_arch=$(normalize_opa_arch "$OPA_ARCH")
elif [ -n "$docker_platform" ]; then
  opa_arch=$(normalize_opa_arch "${docker_platform##*/}")
else
  opa_arch=$(normalize_opa_arch "$(uname -m)")
fi

[ -d "$source_dir" ] || {
  printf 'ScubaGoggles source directory does not exist: %s
' "$source_dir" >&2
  exit 66
}

if [ -z "$opa_binary" ]; then
  command -v curl >/dev/null 2>&1 || {
    printf 'curl is required unless OPA_BINARY points to an existing Linux OPA executable.
' >&2
    exit 67
  }
fi

mkdir -p "$context_dir/scubagoggles-src"
mkdir -p "$context_dir/opa-bin"

rsync -a --delete   --exclude '.git'   --exclude '.venv'   --exclude '__pycache__'   --exclude '.pytest_cache'   --exclude 'build'   --exclude 'dist'   "$source_dir"/ "$context_dir/scubagoggles-src"/

if [ -n "$opa_binary" ]; then
  [ -f "$opa_binary" ] || {
    printf 'OPA_BINARY does not exist: %s
' "$opa_binary" >&2
    exit 68
  }
  cp "$opa_binary" "$context_dir/opa-bin/opa"
else
  opa_url="https://github.com/open-policy-agent/opa/releases/download/$opa_version/opa_linux_${opa_arch}_static"
  curl_insecure=

  if [ "${OPA_DOWNLOAD_INSECURE:-false}" = "true" ]; then
    curl_insecure=-k
  fi

  printf 'Downloading OPA from %s
' "$opa_url"
  if ! curl -fsSL $curl_insecure "$opa_url" -o "$context_dir/opa-bin/opa"; then
    printf '
Unable to download OPA. If this is a corporate TLS certificate issue, either:
' >&2
    printf '  1. Download OPA manually and rerun with OPA_BINARY=/path/to/linux-opa, or
' >&2
    printf '  2. Rerun with OPA_DOWNLOAD_INSECURE=true to let curl skip TLS verification.
' >&2
    exit 69
  fi
fi

chmod 0755 "$context_dir/opa-bin/opa"

cp "$script_dir/Dockerfile" "$context_dir/Dockerfile"
cp "$script_dir/entrypoint.sh" "$context_dir/entrypoint.sh"
cp "$script_dir/.dockerignore" "$context_dir/.dockerignore"

if [ -n "$docker_platform" ]; then
  docker build --platform "$docker_platform" -t "$image_tag" "$context_dir"
else
  docker build -t "$image_tag" "$context_dir"
fi

printf 'Built image: %s
' "$image_tag"
