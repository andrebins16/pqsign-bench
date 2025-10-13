#!/usr/bin/env bash
set -euo pipefail

# ================================================
# Configura CPU governor para performance
# Uso: sudo ./setup_cpu_performance.sh
# ================================================

# Verifica se está rodando como root
if [[ $EUID -ne 0 ]]; then
    echo "ERRO: Execute como root (sudo)"
    exit 1
fi

echo "[setup] Configurando CPU governor para 'performance'..."

# Setar performance em todas CPUs
echo performance | tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor > /dev/null

echo "[setup] Governor configurado para 'performance'"

# Desabilitar Turbo Boost (apenas Intel)
if [[ -f /sys/devices/system/cpu/intel_pstate/no_turbo ]]; then
    echo "1" | tee /sys/devices/system/cpu/intel_pstate/no_turbo > /dev/null
    echo "[setup] Intel Turbo Boost desabilitado"
fi

# Mostrar configuração
echo "[setup] Configuração atual:"
echo "  Governor: $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor)"

echo "[setup] Pronto!