#!/usr/bin/env bash
set -euo pipefail

KEYSTORE_PATH=${1:-"$PWD/ssh2socks-release.p12"}
KEY_ALIAS=${2:-"ssh2socks-release"}

if ! command -v keytool >/dev/null 2>&1; then
  echo "keytool is required. Install a JDK and retry." >&2
  exit 1
fi

if [[ -e "$KEYSTORE_PATH" ]]; then
  echo "Refusing to overwrite existing keystore: $KEYSTORE_PATH" >&2
  exit 1
fi

mkdir -p "$(dirname -- "$KEYSTORE_PATH")"
umask 077
keytool -genkeypair -v \
  -keystore "$KEYSTORE_PATH" \
  -storetype PKCS12 \
  -alias "$KEY_ALIAS" \
  -keyalg RSA \
  -keysize 4096 \
  -validity 10000

chmod 600 "$KEYSTORE_PATH"
printf 'Created keystore: %s\nAlias: %s\n' "$KEYSTORE_PATH" "$KEY_ALIAS"
