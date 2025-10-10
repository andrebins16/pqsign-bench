#!/usr/bin/env bash
set -euo pipefail

# ================================================
# Setup de dependências para BenchExec (Raspberry Pi)
# Instala ferramentas, configura cgroups v2, PSI, systemd --user
# ================================================

# Funções de log
timestamp() { date +"%H:%M:%S"; }
log()  { echo "[$(timestamp)] $*"; }
info() { echo "[$(timestamp)] [info] $*"; }
ok()   { echo "[$(timestamp)] [ok] $*"; }
warn() { echo "[$(timestamp)] [warn] $*" >&2; }

# Variáveis globais
NEED_REBOOT=0
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="python3"
USER_ID="$(id -u)"
CGROUP_BASE="/sys/fs/cgroup"
VENV_PATH="$HOME/.venvs/benchexec"

# Detecção do sistema
# shellcheck source=/dev/null
. /etc/os-release 2>/dev/null || true

DISTRO_ID="${ID:-unknown}"
DISTRO_ID_LIKE="${ID_LIKE:-}"
DISTRO_CODENAME="${UBUNTU_CODENAME:-${VERSION_CODENAME:-N/A}}"
HOST_ARCH="$(dpkg --print-architecture 2>/dev/null || echo unknown)"

log "Sistema: ${DISTRO_ID}/${DISTRO_ID_LIKE} codename=${DISTRO_CODENAME} arch=${HOST_ARCH}"

# Instalação de pacotes base via APT

log "Atualizando índices do APT..."
sudo rm -rf /var/lib/apt/lists/* || true
sudo apt -qq update

log "Instalando ferramentas de compilação e desenvolvimento..."
sudo apt -qq -y install build-essential cmake ninja-build git pkg-config curl wget unzip libssl-dev ca-certificates

log "Instalando ferramentas de isolamento (host)..."
sudo apt -qq -y install fuse-overlayfs libseccomp2 lxcfs uidmap bubblewrap >/dev/null

# Python e ambiente virtual

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

# User namespaces e overlay filesystem

log "Configurando user namespaces e overlay filesystem..."

# Habilita user namespaces não privilegiados (best-effort)
if [[ -w /proc/sys/kernel/unprivileged_userns_clone ]]; then
    sudo sysctl -q -w kernel.unprivileged_userns_clone=1 || true
fi

# Carrega módulo overlay
sudo modprobe overlay >/dev/null 2>&1 || true

# Configuração do systemd --user

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

# Configuração de cgroups

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

# Configuração de PSI (Pressure Stall Information)

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

# Desativação de SWAP

disable_swap() {
    log "Desativando SWAP (para resultados reprodutíveis em benchmarks)..."
    
    # Desabilita serviços de swap comuns
    sudo systemctl disable --now dphys-swapfile 2>/dev/null || true
    sudo systemctl disable --now zramswap 2>/dev/null || true
    
    # Desativa swap ativo
    sudo swapoff -a || true
    
    # Remove arquivo de swap padrão se existir
    if [[ -f /var/swap ]]; then
        sudo rm -f /var/swap || true
    fi
    
    # Configura swappiness=0 (fallback caso swap seja reativado)
    echo 'vm.swappiness=0' | sudo tee /etc/sysctl.d/99-swap-tuning.conf >/dev/null
    sudo sysctl -q -p /etc/sysctl.d/99-swap-tuning.conf || true
    
    # Verifica se swap foi desativado com sucesso
    if [[ -n "$(swapon --show 2>/dev/null)" ]]; then
        warn "Ainda há swap ativo (verifique serviços customizados)."
    else
        ok "Swap desativado com sucesso."
    fi
}

disable_swap

# Configuração permanente de PATH

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

# Verificação e testes

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

ok "Setup de dependências concluído."

if [[ $NEED_REBOOT -eq 1 ]]; then
    echo
    echo "************** REBOOT NECESSÁRIO **************"
    echo "* Foi aplicado 'psi=1' e/ou Delegate=yes pode requerer novo boot."
    echo "* Execute:  sudo reboot"
    echo "***********************************************"
fi
echo "==============================================="