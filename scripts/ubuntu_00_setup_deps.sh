#!/usr/bin/env bash
set -euo pipefail

# ================================================
# Setup de dependências para Ubuntu (local x86_64)
# Instala ferramentas de build, Python, BenchExec e desativa swap
# ================================================

# ---------- Funções de log ----------
log()  { echo "[deps] $*"; }
ok()   { echo "[deps] [ok] $*"; }
warn() { echo "[deps] [warn] $*" >&2; }

# ---------- Variáveis globais ----------
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# ---------- Detecção do sistema ----------
log "Detectando ambiente..."

# shellcheck source=/dev/null
. /etc/os-release

HOST_ARCH="$(dpkg --print-architecture)"  # amd64 ou arm64
DISTRO_CODENAME="${UBUNTU_CODENAME:-jammy}"
DISTRO_ID_LIKE="${ID_LIKE:-}"
DISTRO_ID="${ID:-}"

log "Sistema: UBUNTU_CODENAME=${DISTRO_CODENAME}, HOST_ARCH=${HOST_ARCH}, ID=${DISTRO_ID} ID_LIKE=${DISTRO_ID_LIKE}"

# ---------- Configuração de sources do APT ----------

# Desabilita ubuntu.sources para evitar duplicidades/404 em ARM64
if [[ -f /etc/apt/sources.list.d/ubuntu.sources ]]; then
    log "Desabilitando ubuntu.sources..."
    sudo mkdir -p /etc/apt/disabled-sources
    sudo mv /etc/apt/sources.list.d/ubuntu.sources "/etc/apt/disabled-sources/ubuntu.sources.$(date +%s)" || true
fi

# ---------- Atualização e instalação de pacotes base ----------

log "Atualizando índices do APT (limpando cache antigo)..."
sudo rm -rf /var/lib/apt/lists/*
sudo apt update

log "Instalando dependências de compilação..."
sudo apt install -y build-essential cmake ninja-build git pkg-config curl wget unzip libssl-dev

# ---------- Python e dependências ----------

log "Verificando instalação do Python..."
sudo apt install -y python3 python3-venv python3-pip

# Valida versão mínima do Python
python3 - <<'PYTHON_CHECK'
import sys
major, minor = sys.version_info[:2]
assert (major, minor) >= (3,10), f"Python >= 3.10 requerido, encontrado {major}.{minor}"
PYTHON_CHECK

log "Python $(python3 -c 'import sys; print(f\"{sys.version_info.major}.{sys.version_info.minor}\")') ok."

log "Instalando dependências Python via APT (sem venv)..."
sudo apt install -y python3-jinja2 python3-yaml python3-tabulate python3-tomli

# ---------- Instalação do BenchExec ----------

# Instala BenchExec via PPA oficial (para Ubuntu)
install_benchexec_apt() {
    log "Instalando BenchExec via PPA oficial..."
    sudo apt install -y software-properties-common
    sudo add-apt-repository -y ppa:sosy-lab/benchmarking
    sudo apt update

    # Pacote principal
    sudo apt install -y benchexec

    # Extras
    sudo apt install -y libseccomp2 lxcfs python3-pystemd python3-coloredlogs || true

    # intel-cmt-cat (Intel CAT/L3): apenas para x86_64 Intel
    if [[ "$HOST_ARCH" == "amd64" ]]; then
        sudo apt install -y intel-cmt-cat || true
    fi
}

# Instala BenchExec via pip (para Debian/Raspberry Pi OS ou fallback)
install_benchexec_pip() {
    log "Instalando BenchExec via pip..."
    
    # Tenta instalar com extra [systemd]
    if ! pip3 install --user 'benchexec[systemd]' coloredlogs; then
        warn "Falha ao instalar com extra [systemd], tentando sem..."
        pip3 install --user benchexec coloredlogs || true
    fi
    
    # pystemd: integração com systemd (tenta APT primeiro, depois pip)
    sudo apt install -y python3-pystemd || pip3 install --user pystemd || true
}

# Detecta estratégia de instalação (PPA para Ubuntu, pip para outros)
log "Detectando estratégia de instalação do BenchExec..."
IS_UBUNTU=0
if [[ "$DISTRO_ID" == "ubuntu" ]] || [[ "$DISTRO_ID_LIKE" == *"ubuntu"* ]]; then
    IS_UBUNTU=1
fi

if [[ $IS_UBUNTU -eq 1 ]]; then
    install_benchexec_apt
else
    install_benchexec_pip
fi

# ---------- Verificação da instalação ----------

log "Verificando versões instaladas..."

if command -v runexec >/dev/null 2>&1; then
    ok "$(runexec --version | head -n1)"
else
    warn "runexec não encontrado no PATH. Se instalou via pip, adicione ~/.local/bin ao PATH."
fi

if command -v benchexec >/dev/null 2>&1; then
    ok "$(benchexec --version | head -n1)"
else
    warn "benchexec não encontrado no PATH. Se instalou via pip, adicione ~/.local/bin ao PATH."
fi

if command -v table-generator >/dev/null 2>&1; then
    ok "table-generator disponível"
else
    warn "table-generator não encontrado no PATH."
fi

# ---------- Desativação de SWAP ----------

disable_swap() {
    log "Desativando SWAP (para reprodutibilidade em benchmarks)..."
    
    # Desativa swap imediatamente
    sudo swapoff -a || true

    # Comenta entradas de swap no /etc/fstab
    if [[ -r /etc/fstab ]]; then
        sudo cp -a /etc/fstab "/etc/fstab.bak.$(date +%s)"
        
        # Comenta linhas com 'swap' no campo de tipo de filesystem
        sudo awk 'BEGIN{OFS="\t"} $3=="swap"{print "#",$0; next} {print}' /etc/fstab > /tmp/fstab.noswap
        
        if ! diff -q /etc/fstab /tmp/fstab.noswap >/dev/null 2>&1; then
            sudo mv /tmp/fstab.noswap /etc/fstab
            log "Entradas de swap comentadas em /etc/fstab (backup criado)."
        else
            rm -f /tmp/fstab.noswap
        fi
    fi

    # Remove arquivo de swap padrão se existir
    if [[ -f /swapfile ]]; then
        sudo rm -f /swapfile || true
    fi

    # Configura swappiness=0 (fallback caso swap seja reativado)
    echo 'vm.swappiness=0' | sudo tee /etc/sysctl.d/99-swap-tuning.conf >/dev/null
    sudo sysctl -q -p /etc/sysctl.d/99-swap-tuning.conf || true

    # Desabilita serviços de ZRAM (Ubuntu)
    sudo systemctl disable --now systemd-zram-setup@zram0.service 2>/dev/null || true
    sudo systemctl disable --now zram-generator 2>/dev/null || true

    # Verifica se swap foi desativado com sucesso
    if [[ -n "$(swapon --show 2>/dev/null)" ]]; then
        warn "Ainda há swap ativo (verifique unidades/customizações locais)."
    else
        ok "SWAP desativado com sucesso."
    fi
}

disable_swap

ok "Setup de dependências concluído."