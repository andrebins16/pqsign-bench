#!/usr/bin/env bash
set -euo pipefail

# ================================================
# Build de liboqs, oqs-provider e aplicação (Raspberry Pi - Native)
# Compila todas as dependências e binários para arquitetura nativa
# ================================================

# ---------- Funções de log ----------
log()  { echo "[build] $*"; }
ok()   { echo "[build] [ok] $*"; }
error() { echo "[build] [ERRO] $*" >&2; }

# ---------- Variáveis globais ----------
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROOT="${ROOT%/}"

EXTERN_DIR="$ROOT/extern"
LOCAL_DIR="$ROOT/local"
OSSL_MODULES_DIR="$ROOT/ossl-modules"
BUILD_DIR="$ROOT/build"
LOGS_DIR="$ROOT/logs"

# Remove trailing slashes
EXTERN_DIR="${EXTERN_DIR%/}"
LOCAL_DIR="${LOCAL_DIR%/}"
OSSL_MODULES_DIR="${OSSL_MODULES_DIR%/}"
BUILD_DIR="${BUILD_DIR%/}"
LOGS_DIR="${LOGS_DIR%/}"

# Cria diretórios necessários
mkdir -p "$LOCAL_DIR/native" "$OSSL_MODULES_DIR/native" "$BUILD_DIR/native" "$LOGS_DIR"

# ---------- Build: liboqs (native) ----------

build_liboqs_native() {
    log "Compilando liboqs (native) -> $LOCAL_DIR/native"
    
    local liboqs_build_dir="$EXTERN_DIR/liboqs/build-native"
    
    # Remove build anterior
    rm -rf "$liboqs_build_dir"
    
    # Configura build
    cmake -G Ninja -S "$EXTERN_DIR/liboqs" -B "$liboqs_build_dir" \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_SHARED_LIBS=ON \
        -DOQS_BUILD_ONLY_LIB=ON \
        -DOQS_DIST_BUILD=ON \
        -DCMAKE_INSTALL_PREFIX="$LOCAL_DIR/native" \
        2>&1 | tee "$LOGS_DIR/liboqs_native_configure.log"
    
    # Compila
    cmake --build "$liboqs_build_dir" -j"$(nproc)" \
        2>&1 | tee "$LOGS_DIR/liboqs_native_build.log"
    
    # Instala
    cmake --install "$liboqs_build_dir" \
        2>&1 | tee "$LOGS_DIR/liboqs_native_install.log"
    
    ok "liboqs (native) instalado em $LOCAL_DIR/native"
}

# ---------- Build: oqs-provider (native) ----------

build_oqs_provider_native() {
    log "Compilando oqs-provider (native) -> $OSSL_MODULES_DIR/native"
    
    local oqsp_build_dir="$EXTERN_DIR/oqs-provider/build-native"
    
    # Remove build anterior
    rm -rf "$oqsp_build_dir"
    
    # Configura build (usa liboqs instalado em LOCAL_DIR/native)
    cmake -G Ninja -S "$EXTERN_DIR/oqs-provider" -B "$oqsp_build_dir" \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_PREFIX_PATH="$LOCAL_DIR/native" \
        2>&1 | tee "$LOGS_DIR/oqsp_native_configure.log"
    
    # Compila
    cmake --build "$oqsp_build_dir" -j"$(nproc)" \
        2>&1 | tee "$LOGS_DIR/oqsp_native_build.log"
    
    # Verifica se oqsprovider.so foi gerado
    local provider_so="$oqsp_build_dir/lib/oqsprovider.so"
    if [[ ! -f "$provider_so" ]]; then
        error "oqsprovider.so não encontrado em $oqsp_build_dir/lib/"
        error "Verifique o log: $LOGS_DIR/oqsp_native_build.log"
        exit 1
    fi
    
    # Copia provider para diretório de módulos OpenSSL
    cp "$provider_so" "$OSSL_MODULES_DIR/native/"
    
    ok "oqs-provider (native) instalado em $OSSL_MODULES_DIR/native"
}

# ---------- Build: aplicação (native) ----------

build_app_native() {
    log "Compilando aplicação (native) -> $BUILD_DIR/native"
    
    local app_build_dir="$BUILD_DIR/native"
    
    # Remove build anterior
    rm -rf "$app_build_dir"
    
    # Configura build (usa liboqs instalado em LOCAL_DIR/native)
    cmake -G Ninja -S "$ROOT/src" -B "$app_build_dir" \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_PREFIX_PATH="$LOCAL_DIR/native" \
        2>&1 | tee "$LOGS_DIR/app_native_configure.log"
    
    # Compila
    cmake --build "$app_build_dir" -j"$(nproc)" \
        2>&1 | tee "$LOGS_DIR/app_native_build.log"
    
    ok "Aplicação (native) compilada em $BUILD_DIR/native"
    log "Binários disponíveis:"
    log "  - bench_worker: $BUILD_DIR/native/bench_worker"
    log "  - bench_prep:   $BUILD_DIR/native/bench_prep"
}

# ---------- Execução do build ----------

log "Iniciando build nativo (Raspberry Pi)..."

build_liboqs_native
build_oqs_provider_native
build_app_native

ok "Build nativo finalizado com sucesso."
log "Logs salvos em: $LOGS_DIR/"