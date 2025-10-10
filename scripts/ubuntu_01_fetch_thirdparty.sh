#!/usr/bin/env bash
set -euo pipefail

# ================================================
# Fetch de dependências third-party (Ubuntu)
# Baixa liboqs e oqs-provider com commits fixos
# ================================================

# ---------- Funções de log ----------
log()  { echo "[fetch] $*"; }
ok()   { echo "[fetch] [ok] $*"; }
warn() { echo "[fetch] [warn] $*" >&2; }
error() { echo "[fetch] [ERRO] $*" >&2; }

# ---------- Variáveis globais ----------
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXTERN_DIR="$ROOT/extern"

# Commits fixos dos repositórios third-party (podem ser sobrescritos via env)
LIBOQS_COMMIT="${LIBOQS_COMMIT:-94b421ebb82405c843dba4e9aa521a56ee5a333d}"
OQSPROVIDER_COMMIT="${OQSP_COMMIT:-f076e91faab88871ff1973db0287cc6e4b94c4b0}"

mkdir -p "$EXTERN_DIR"

# ---------- Funções auxiliares ----------

# Clona ou atualiza repositório
clone_or_update_repo() {
    local repo_url="$1"
    local dest_dir="$2"
    
    if [[ ! -d "$dest_dir/.git" ]]; then
        log "Clonando $(basename "$dest_dir")..."
        git clone --depth=1 "$repo_url" "$dest_dir"
    else
        log "Atualizando $(basename "$dest_dir")..."
        (cd "$dest_dir" && git pull --ff-only)
    fi
}

# Posiciona repositório em commit específico
checkout_specific_commit() {
    local repo_dir="$1"
    local target_commit="$2"
    
    (
        cd "$repo_dir"
        
        # Garante que não há mudanças locais
        git reset --hard >/dev/null
        
        # Tenta checkout direto; se falhar, faz fetch
        if ! git checkout --quiet "$target_commit" 2>/dev/null; then
            log "Commit $target_commit não encontrado em $(basename "$repo_dir"). Buscando..."
            git fetch --depth=1 origin "$target_commit"
            git checkout --quiet "$target_commit"
        fi
        
        # Valida que está no commit correto
        local current_commit
        current_commit="$(git rev-parse HEAD)"
        if [[ "$current_commit" != "$target_commit" ]]; then
            error "Falha ao posicionar $(basename "$repo_dir") no commit desejado."
            error "  Esperado: $target_commit"
            error "  Obtido:   $current_commit"
            exit 1
        fi
        
        ok "$(basename "$repo_dir") fixado em $(git rev-parse --short HEAD)"
    )
}

# ---------- Download de repositórios third-party ----------

log "Baixando liboqs e oqs-provider (commits fixos)..."

# liboqs
clone_or_update_repo "https://github.com/open-quantum-safe/liboqs.git" "$EXTERN_DIR/liboqs"
checkout_specific_commit "$EXTERN_DIR/liboqs" "$LIBOQS_COMMIT"
(cd "$EXTERN_DIR/liboqs" && git submodule update --init --recursive)

# oqs-provider
clone_or_update_repo "https://github.com/open-quantum-safe/oqs-provider.git" "$EXTERN_DIR/oqs-provider"
checkout_specific_commit "$EXTERN_DIR/oqs-provider" "$OQSPROVIDER_COMMIT"
(cd "$EXTERN_DIR/oqs-provider" && git submodule update --init --recursive)

ok "Repositórios third-party prontos em extern/."

# ---------- Atualização do generate.yml do oqs-provider ----------

SOURCE_YML="$ROOT/scripts/generateOqsProviderUpdated.yml"
DEST_DIR="$EXTERN_DIR/oqs-provider/oqs-template"
DEST_YML="$DEST_DIR/generate.yml"

log "Atualizando generate.yml do oqs-provider..."

# Valida existência dos arquivos/diretórios
if [[ ! -f "$SOURCE_YML" ]]; then
    error "Arquivo não encontrado: $SOURCE_YML"
    exit 1
fi

if [[ ! -d "$DEST_DIR" ]]; then
    error "Diretório não encontrado: $DEST_DIR"
    exit 1
fi

# Faz backup do arquivo original se existir
if [[ -f "$DEST_YML" ]]; then
    cp -f "$DEST_YML" "$DEST_YML.bak.$(date +%s)"
    log "Backup criado: $DEST_YML.bak.<timestamp>"
fi

# Copia arquivo atualizado
cp -f "$SOURCE_YML" "$DEST_YML"
ok "Copiado: $SOURCE_YML -> $DEST_YML"

# ---------- Execução do generate.py ----------

log "Executando generate.py do oqs-provider..."
(
    cd "$EXTERN_DIR/oqs-provider"
    export LIBOQS_SRC_DIR="$(pwd)/../liboqs"
    log "LIBOQS_SRC_DIR=$LIBOQS_SRC_DIR"
    python3 oqs-template/generate.py
)
ok "generate.py concluído."

ok "Setup de dependências externas concluído."
