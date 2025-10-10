#!/usr/bin/env bash
# Só habilita -euo pipefail se o script for EXECUTADO diretamente (não via "source")
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  set -euo pipefail
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

export OPENSSL_CONF="$ROOT/env/openssl-oqs.cnf"
export OPENSSL_MODULES="$ROOT/ossl-modules/native"
export LD_LIBRARY_PATH="${LD_LIBRARY_PATH:-}:$ROOT/local/native/lib"

echo "OPENSSL_CONF=$OPENSSL_CONF"
echo "OPENSSL_MODULES=$OPENSSL_MODULES"
echo "LD_LIBRARY_PATH=$LD_LIBRARY_PATH"
echo
echo "Providers detectados:"
# Se falhar, não derruba seu shell
openssl list -providers || true
