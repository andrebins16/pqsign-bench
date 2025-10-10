#!/usr/bin/env bash
set -euo pipefail

# ================================================
# Fetch e setup de dependências third-party (Raspberry Pi)
# Baixa liboqs e oqs-provider com commits fixos
# Configura BenchExec, cgroups v2, PSI e systemd --user
# ================================================

# ---------- Funções de log ----------
timestamp() { date +"%H:%M:%S"; }
log()  { echo "[$(timestamp)] $*"; }
info() { echo "[$(timestamp)] [info] $*"; }
ok()   { echo "[$(timestamp)] [ok] $*"; }
warn() { echo "[$(timestamp)] [warn] $*" >&2; }

# ---------- Variáveis globais ----------
NEED_REBOOT=0
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="python3"
USER_ID="$(id -u)"
CGROUP_BASE="/sys/fs/cgroup"
VENV_PATH="$HOME/.venvs/benchexec"

# Commits fixos dos repositórios third-party (podem ser sobrescritos via env)
LIBOQS_COMMIT="${LIBOQS_COMMIT:-94b421ebb82405c843dba4e9aa521a56ee5a333d}"
OQSPROVIDER_COMMIT="${OQSP_COMMIT:-f076e91faab88871ff1973db0287cc6e4b94c4b0}"

# ---------- Detecção do sistema ----------
# shellcheck source=/dev/null
. /etc/os-release 2>/dev/null || true

DISTRO_ID="${ID:-unknown}"
DISTRO_ID_LIKE="${ID_LIKE:-}"
DISTRO_CODENAME="${UBUNTU_CODENAME:-${VERSION_CODENAME:-N/A}}"
HOST_ARCH="$(dpkg --print-architecture 2>/dev/null || echo unknown)"

log "Sistema: ${DISTRO_ID}/${DISTRO_ID_LIKE} codename=${DISTRO_CODENAME} arch=${HOST_ARCH}"

# ---------- Instalação de pacotes base via APT ----------

log "Atualizando índices do APT..."
sudo rm -rf /var/lib/apt/lists/* || true
sudo apt -qq update

log "Instalando ferramentas de compilação e desenvolvimento..."
sudo apt -qq -y install build-essential cmake ninja-build git pkg-config curl wget unzip libssl-dev ca-certificates

log "Instalando ferramentas de isolamento (host)..."
sudo apt -qq -y install fuse-overlayfs libseccomp2 lxcfs uidmap bubblewrap >/dev/null

# ---------- Python e ambiente virtual ----------

log "Instalando Python e venv..."
sudo apt -qq -y install python3 python3-venv python3-pip python3-full >/dev/null

# Valida versão mínima do Python
$PYTHON_BIN - <<'PYTHON_CHECK'
import sys
assert sys.version_info[:2] >= (3,10), f"Python >=3.10 requerido, encontrado {sys.version_info[0]}.{sys.version_info[1]}"
print(f"Python {sys.version_info[0]}.{sys.version_info[1]} ok.")
PYTHON_CHECK

# Cria ambiente virtual se não existir
mkdir -p "$(dirname "$VENV_PATH")"
if [[ ! -d "$VENV_PATH" ]]; then
    log "Criando ambiente virtual em ${VENV_PATH}..."
    $PYTHON_BIN -m venv "$VENV_PATH"
fi

# Ativa venv e atualiza pip
# shellcheck disable=SC1091
source "$VENV_PATH/bin/activate"
pip -q install -U pip >/dev/null

# Instala BenchExec e dependências Python
log "Instalando BenchExec e dependências Python no venv..."
pip -q install benchexec[systemd] coloredlogs pystemd jinja2 PyYAML tomli tabulate >/dev/null
ok "BenchExec e bibliotecas Python instalados no venv."

# ---------- User namespaces e overlay filesystem ----------

log "Configurando user namespaces e overlay filesystem..."

# Habilita user namespaces não privilegiados (best-effort)
if [[ -w /proc/sys/kernel/unprivileged_userns_clone ]]; then
    sudo sysctl -q -w kernel.unprivileged_userns_clone=1 || true
fi

# Carrega módulo overlay
sudo modprobe overlay >/dev/null 2>&1 || true

# ---------- Configuração do systemd --user ----------

# Garante delegação de cgroups para systemd --user
ensure_systemd_user_delegation() {
    sudo apt -qq -y install libpam-systemd >/dev/null || true
    
    if ! command -v systemctl >/dev/null 2>&1; then
        warn "systemctl não encontrado; pulando configuração de delegação."
        return
    fi
    
    # Verifica se Delegate=yes já está configurado
    if ! systemctl cat user@.service 2>/dev/null | grep -q '^\s*Delegate=yes'; then
        log "Aplicando Delegate=yes em user@.service..."
        sudo mkdir -p /etc/systemd/system/user@.service.d
        sudo tee /etc/systemd/system/user@.service.d/delegate.conf >/dev/null <<'EOF'
[Service]
Delegate=yes
EOF
        sudo systemctl daemon-reload || true
        NEED_REBOOT=1  # Pode requerer novo login/boot para efetivar
    else
        ok "Delegate=yes já presente em user@.service."
    fi
    
    # Habilita linger para manter systemd --user ativo
    sudo loginctl enable-linger "$USER" >/dev/null 2>&1 || true
}

# Garante que systemd --user está ativo
ensure_systemd_user_active() {
    if systemctl --user is-active default >/dev/null 2>&1; then
        ok "systemd --user está ativo."
        return
    fi
    
    # Tenta ativar systemd --user
    systemctl --user daemon-reload >/dev/null 2>&1 || true
    systemd-run --user --scope -p Delegate=yes true >/dev/null 2>&1 || true
    
    if ! systemctl --user is-active default >/dev/null 2>&1; then
        warn "systemd --user pode precisar de novo login (ou: loginctl restart-user $USER)."
    fi
}

ensure_systemd_user_delegation
ensure_systemd_user_active

# ---------- Configuração de cgroups ----------

# Detecta versão de cgroups (v1 ou v2)
CGROUPS_V2=0
if [[ -f "$CGROUP_BASE/cgroup.controllers" ]]; then
    CGROUPS_V2=1
    ok "cgroups v2 detectado."
else
    info "cgroups v1/híbrido detectado."
fi

# Delega cpuset para cgroups v2
delegate_cpuset_controllers() {
    local cgroup_paths=(
        "$CGROUP_BASE/user.slice/cgroup.subtree_control"
        "$CGROUP_BASE/user.slice/user-${USER_ID}.slice/cgroup.subtree_control"
        "$CGROUP_BASE/user.slice/user-${USER_ID}.slice/user@${USER_ID}.service/cgroup.subtree_control"
        "$CGROUP_BASE/user.slice/user-${USER_ID}.slice/user@${USER_ID}.service/app.slice/cgroup.subtree_control"
        "$CGROUP_BASE/user.slice/user-${USER_ID}.slice/user@${USER_ID}.service/benchexec.slice/cgroup.subtree_control"
    )
    
    log "Delegando controlador cpuset (+cpuset)..."
    for cgroup_file in "${cgroup_paths[@]}"; do
        [[ -f "$cgroup_file" ]] || continue
        if ! grep -qw '\+cpuset' "$cgroup_file" 2>/dev/null; then
            echo +cpuset | sudo tee "$cgroup_file" >/dev/null || true
        fi
    done
}

if [[ $CGROUPS_V2 -eq 1 ]]; then
    delegate_cpuset_controllers
fi

# ---------- Configuração de PSI (Pressure Stall Information) ----------

configure_psi() {
    log "Verificando PSI (Pressure Stall Information)..."
    
    # Verifica se PSI já está ativo
    if [[ -f /proc/pressure/cpu ]] || [[ -f "$CGROUP_BASE/cpu.pressure" ]]; then
        ok "PSI já está ativo."
        return
    fi
    
    # Carrega módulo configs para ler configuração do kernel
    sudo modprobe configs >/dev/null 2>&1 || true
    
    local kernel_config="/proc/config.gz"
    local psi_enabled=""
    local psi_default_disabled=""
    
    if [[ -r "$kernel_config" ]]; then
        psi_enabled="$(zgrep -E '^CONFIG_PSI=' "$kernel_config" || true)"
        psi_default_disabled="$(zgrep -E '^CONFIG_PSI_DEFAULT_DISABLED=' "$kernel_config" || true)"
    fi
    
    # Detecta arquivo de cmdline (varia entre sistemas)
    local cmdline_file=""
    if sudo test -f /boot/firmware/cmdline.txt; then
        cmdline_file="/boot/firmware/cmdline.txt"
    elif sudo test -f /boot/cmdline.txt; then
        cmdline_file="/boot/cmdline.txt"
    fi
    
    # Habilita PSI via cmdline se kernel suportar
    if echo "$psi_enabled" | grep -q 'CONFIG_PSI=y'; then
        log "Kernel com suporte a PSI; habilitando via 'psi=1'..."
        
        if [[ -n "$cmdline_file" ]] && ! sudo grep -qw 'psi=1' "$cmdline_file"; then
            # Faz backup antes de modificar
            sudo cp -a "$cmdline_file" "$cmdline_file.bak.$(date +%s)"
            sudo sed -i 's/$/ psi=1/' "$cmdline_file"
            NEED_REBOOT=1
            ok "Adicionado 'psi=1' em ${cmdline_file} (reboot necessário)."
        else
            info "Não foi possível localizar cmdline ou 'psi=1' já presente."
        fi
    else
        warn "CONFIG_PSI não habilitado neste kernel (check_cgroups pode avisar)."
    fi
}

configure_psi

# ---------- Configuração permanente de PATH ----------

configure_path_exports() {
    log "Configurando PATH permanente para o venv..."
    
    local path_export='export PATH="$HOME/.venvs/benchexec/bin:$HOME/.local/bin:$PATH"'
    
    if ! grep -q '.venvs/benchexec/bin' "$HOME/.profile" 2>/dev/null; then
        echo "$path_export" >> "$HOME/.profile"
        ok "PATH adicionado ao ~/.profile."
    else
        ok "PATH do venv já presente no ~/.profile."
    fi
    
    # Cria symlinks em ~/.local/bin
    mkdir -p "$HOME/.local/bin"
    ln -sf "$VENV_PATH/bin/runexec"         "$HOME/.local/bin/runexec"
    ln -sf "$VENV_PATH/bin/benchexec"       "$HOME/.local/bin/benchexec"
    ln -sf "$VENV_PATH/bin/table-generator" "$HOME/.local/bin/table-generator" || true
}

configure_path_exports

# ---------- Download de repositórios third-party ----------

EXTERN_DIR="$ROOT/extern"
mkdir -p "$EXTERN_DIR"

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
            echo "[ERRO] Falha ao posicionar $(basename "$repo_dir") no commit desejado." >&2
            echo "Esperado: $target_commit" >&2
            echo "Obtido:   $current_commit" >&2
            exit 1
        fi
        
        ok "$(basename "$repo_dir") fixado em $(git rev-parse --short HEAD)"
    )
}

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
    echo "[ERRO] Arquivo não encontrado: $SOURCE_YML" >&2
    exit 1
fi

if [[ ! -d "$DEST_DIR" ]]; then
    echo "[ERRO] Diretório não encontrado: $DEST_DIR" >&2
    exit 1
fi

# Faz backup do arquivo original se existir
if [[ -f "$DEST_YML" ]]; then
    cp -f "$DEST_YML" "$DEST_YML.bak.$(date +%s)"
    info "Backup criado: $DEST_YML.bak.<timestamp>"
fi

# Copia arquivo atualizado
cp -f "$SOURCE_YML" "$DEST_YML"
ok "Copiado: $SOURCE_YML -> $DEST_YML"

# Executa generate.py do oqs-provider
log "Executando generate.py do oqs-provider..."
(
    cd "$EXTERN_DIR/oqs-provider"
    export LIBOQS_SRC_DIR="$(pwd)/../liboqs"
    info "LIBOQS_SRC_DIR=$LIBOQS_SRC_DIR"
    "$PYTHON_BIN" oqs-template/generate.py
)
ok "generate.py concluído."

# ---------- Verificação e testes ----------

log "Verificando instalação do BenchExec..."
ok "$("$VENV_PATH/bin/runexec" --version | head -n1)"
ok "$("$VENV_PATH/bin/benchexec" --version | head -n1)"

# Executa check_cgroups do BenchExec
if command -v systemd-run >/dev/null 2>&1; then
    log "Executando check_cgroups (scope systemd --user)..."
    if systemd-run --user --scope -p Delegate=yes "$PYTHON_BIN" -m benchexec.check_cgroups; then
        ok "Verificação de cgroups passou."
    else
        warn "check_cgroups reportou problemas (veja mensagens acima)."
    fi
fi

ok "Setup de dependências externas concluído."

if [[ $NEED_REBOOT -eq 1 ]]; then
    echo
    echo "************** REBOOT NECESSÁRIO **************"
    echo "* Foi aplicado 'psi=1' e/ou Delegate=yes pode requerer novo boot."
    echo "* Execute:  sudo reboot"
    echo "***********************************************"
fi
echo "==============================================="