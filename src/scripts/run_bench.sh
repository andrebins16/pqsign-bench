#!/usr/bin/env bash
set -euo pipefail

# ================================================
# Script de benchmark para algoritmos de assinatura digital
# Subcomandos:
#   list-algs : Lista algoritmos disponíveis
#   run       : Executa benchmark com runexec (BenchExec)
# ================================================

# Localização / Paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
BUILD_DIR="${ROOT}/build/native"
WORKER="${BUILD_DIR}/bench_worker"
PREP="${BUILD_DIR}/bench_prep"

# Defaults
ALGS_DEFAULT="sphincsshake256ssimple,sphincsshake256fsimple,sphincsshake192ssimple,sphincsshake192fsimple,sphincsshake128ssimple,sphincsshake128fsimple,sphincssha2256ssimple,sphincssha2256fsimple,sphincssha2192ssimple,sphincssha2192fsimple,sphincssha2128ssimple,sphincssha2128fsimple,mldsa87,mldsa65,mldsa44,falcon512,falcon1024,RSA,EC"
OPS_DEFAULT="keygen,sign,verify,all"
REPS_DEFAULT=100
SIZES_DEFAULT="10000000, 100000000, 1000000000"
OUTDIR_DEFAULT="${ROOT}/results"
OUTFILE_DEFAULT="results.csv"
TRIM_PCT_DEFAULT=15
BASELINE_DEFAULT=0

# Opções do runexec - Defaults para Ubuntu
TIMELIMIT_DEFAULT="2"
WALLTIMELIMIT_DEFAULT="3"
MEMLIMIT_DEFAULT="100663296" # 96 MB em bytes (96 × 1024 × 1024)
CORES_DEFAULT="0"

# Valores atuais (podem ser sobrescritos por CLI)
ALGS="${ALGS_DEFAULT}"
OPS="${OPS_DEFAULT}"
REPS="${REPS_DEFAULT}"
SIZES="${SIZES_DEFAULT}"
OUTDIR="${OUTDIR_DEFAULT}"
OUTFILE="${OUTFILE_DEFAULT}"
TRIM_PCT="${TRIM_PCT_DEFAULT}"
BASELINE="${BASELINE_DEFAULT}"
TIMELIMIT="${TIMELIMIT_DEFAULT}"
WALLTIMELIMIT="${WALLTIMELIMIT_DEFAULT}"
MEMLIMIT="${MEMLIMIT_DEFAULT}"
CORES="${CORES_DEFAULT}"

# Ambiente OpenSSL/OQS
export OPENSSL_CONF="${ROOT}/env/openssl-oqs.cnf"
export OPENSSL_MODULES="${ROOT}/ossl-modules/native"
export OSSL_PROVIDER_PATH="${OPENSSL_MODULES}"
export LD_LIBRARY_PATH="${ROOT}/local/native/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

# Funções auxiliares

usage() {
    cat <<EOF
Uso: $(basename "$0") SUBCOMANDO [opções]

Subcomandos:
  list-algs              Lista todos os algoritmos de assinatura disponíveis
  run                    Executa benchmark

Opções para 'run':
  --algs "LISTA"         Algoritmos separados por vírgula (entre aspas)
                         (default: RSA,EC,família SPHINCS,família ML-DSA,família Falcon)
  --ops "LISTA"          Operações separadas por vírgula (entre aspas)
                         Opções: keygen,sign,verify,all
                         (default: ${OPS_DEFAULT})
  --reps N               Número de repetições (default: ${REPS_DEFAULT})
  --sizes "LISTA"        Tamanhos de mensagem em bytes, separados por vírgula (entre aspas)
                         (default: ${SIZES_DEFAULT} = 10MB)
  --outdir DIR           Diretório de saída (default: ${OUTDIR_DEFAULT})
  --outfile NOME.csv     Nome do arquivo CSV (default: ${OUTFILE_DEFAULT})
  --trim-pct P           Percentual de trim para estatística (default: ${TRIM_PCT_DEFAULT})
  --baseline             Ativa medição de baseline para calcular overhead
                         (default: desabilitado) Recomendado ativar.

  Opções do runexec:
  --timelimit VAL        Limite de tempo de CPU em segundos (default: ${TIMELIMIT_DEFAULT}s)
  --walltimelimit VAL    Limite de tempo de parede em segundos (default: ${WALLTIMELIMIT_DEFAULT}s)
  --memlimit VAL         Limite de memória em bytes (default: ${MEMLIMIT_DEFAULT} = 96 MB)
  --cores "LISTA"        Lista de cores a usar (entre aspas se múltiplos)
                         Ex: 0 ou "0,2-3" (default: ${CORES_DEFAULT})

  -h|--help              Mostra esta ajuda

Nota: Para passar listas com múltiplos valores, use aspas duplas e separe por vírgula.
      Exemplo: --algs "mldsa44,falcon512,RSA"

Exemplos:
  # Listar algoritmos disponíveis
  $(basename "$0") list-algs

  # Benchmark rápido com poucos algoritmos
  $(basename "$0") run --algs "mldsa44,falcon512" --reps 50

  # Benchmark completo com baseline e limites customizados
  $(basename "$0") run --baseline --timelimit 5 --memlimit 134217728

  # Múltiplos tamanhos de mensagem
  $(basename "$0") run --sizes "1000000,5000000,10000000"
EOF
}

fail() {
    echo "ERRO: $*" >&2
    exit 2
}

check_binary() {
    local bin_path="$1"
    [[ -x "$bin_path" ]] || fail "binário não encontrado: $bin_path"
}

is_integer() {
    [[ "$1" =~ ^[0-9]+$ ]]
}

is_number() {
    [[ "$1" =~ ^-?[0-9]+([.][0-9]+)?([eE][-+]?[0-9]+)?$ ]]
}

# Converte string separada por vírgulas em array
csv_to_array() {
    local input="$1"
    input="$(echo "$input" | tr ',' ' ')"
    read -r -a ARR <<< "$input"
}

# Escapa string para JSON
json_escape() {
    local str="$1"
    str="${str//\\/\\\\}"
    str="${str//\"/\\\"}"
    str="${str//$'\n'/ }"
    str="${str//$'\r'/ }"
    printf '%s' "$str"
}

# Subcomando: list-algs

cmd_list_algs() {
    check_binary "$WORKER"
    
    if ! bc_init_providers_check; then
        fail "falha ao inicializar providers"
    fi
    
    "${WORKER}" list-algs
}

# Verifica se providers podem ser inicializados
bc_init_providers_check() {
    # Tenta executar list-algs; se falhar, providers não estão disponíveis
    "${WORKER}" list-algs >/dev/null 2>&1
}



# Subcomando: run
# Gera fixtures (chave + assinatura) para um algoritmo e tamanho
generate_fixture() {
    local algorithm="$1"
    local msg_size="$2"
    local temp_file
    
    temp_file="$(mktemp)"
    "${PREP}" gensig --alg "$algorithm" --msg-len "$msg_size" > "$temp_file"
    
    local key_b64 sig_b64
    key_b64="$(head -n1 "$temp_file" | tr -d '\r\n\t ')"
    sig_b64="$(tail -n1 "$temp_file" | tr -d '\r\n\t ')"
    rm -f "$temp_file"
    
    printf '%s;%s\n' "$key_b64" "$sig_b64"
}

# Executa uma operação via runexec e retorna: "exit_code wall cpu mem_mb"
run_single_benchmark() {
    local -a cmd_args=("$@")
    local temp_stdout temp_stderr
    temp_stdout="$(mktemp)"
    temp_stderr="$(mktemp)"
    local runexec_exit=0

    # Monta opções do runexec
    local -a runexec_opts=()
    [[ -n "$TIMELIMIT"     ]] && runexec_opts+=( --timelimit "$TIMELIMIT" )
    [[ -n "$WALLTIMELIMIT" ]] && runexec_opts+=( --walltimelimit "$WALLTIMELIMIT" )
    [[ -n "$MEMLIMIT"      ]] && runexec_opts+=( --memlimit "$MEMLIMIT" )
    [[ -n "$CORES"         ]] && runexec_opts+=( --cores "$CORES" )

    # Executa comando
    if ! runexec "${runexec_opts[@]}" -- "${cmd_args[@]}" >"$temp_stdout" 2>"$temp_stderr"; then
        runexec_exit=$?
    fi

    # Extrai métricas dos outputs do runexec
    local return_value wall_time cpu_time mem_bytes mem_mb
    return_value="$( { grep -E '^returnvalue=' "$temp_stdout" "$temp_stderr" 2>/dev/null | tail -n1 | sed -E 's/.*=([0-9]+)/\1/'; } || true )"
    wall_time="$( { grep -E '^walltime=' "$temp_stdout" "$temp_stderr" 2>/dev/null | tail -n1 | sed -E 's/.*=([0-9.]+)s/\1/'; } || true )"
    [[ -z "$wall_time" ]] && wall_time="$( { grep -E 'time\.wall(time)?[:=][ ]*[0-9.]+' "$temp_stdout" "$temp_stderr" 2>/dev/null | head -n1 | sed -E 's/.*[:=][ ]*([0-9.]+)/\1/'; } || true )"
    cpu_time="$( { grep -E '^cputime=' "$temp_stdout" "$temp_stderr" 2>/dev/null | tail -n1 | sed -E 's/.*=([0-9.]+)s/\1/'; } || true )"
    [[ -z "$cpu_time" ]] && cpu_time="$( { grep -E 'time\.cpu(time)?[:=][ ]*[0-9.]+' "$temp_stdout" "$temp_stderr" 2>/dev/null | head -n1 | sed -E 's/.*[:=][ ]*([0-9.]+)/\1/'; } || true )"
    mem_bytes="$( { grep -E '^memory=[0-9]+B' "$temp_stdout" "$temp_stderr" 2>/dev/null | tail -n1 | sed -E 's/.*=([0-9]+)B/\1/'; } || true )"
    [[ -z "$mem_bytes" ]] && mem_bytes="$( { grep -E 'memory\.peak[:=][ ]*[0-9]+' "$temp_stdout" "$temp_stderr" 2>/dev/null | head -n1 | sed -E 's/.*[:=][ ]*([0-9]+)/\1/'; } || true )"
    
    if [[ -n "$mem_bytes" ]]; then
        mem_mb="$(awk -v bytes="$mem_bytes" 'BEGIN{ printf "%.6f", bytes/1000000.0 }')"
    else
        mem_mb=""
    fi

    # Determina código de saída final
    local final_exit=0
    if [[ "$runexec_exit" != "0" ]]; then
        final_exit="$runexec_exit"
    elif [[ -n "$return_value" && "$return_value" != "0" ]]; then
        final_exit="$return_value"
    fi

    # Debug em caso de erro
    if [[ "$final_exit" != "0" && -n "${BENCH_VERBOSE:-}" ]]; then
        echo "[debug] stderr do runexec (últimas 20 linhas):" >&2
        tail -n 20 "$temp_stderr" >&2 || true
    fi

    rm -f "$temp_stdout" "$temp_stderr"

    # Retorna valores (NaN se não coletado)
    [[ -z "$wall_time" ]] && wall_time="NaN"
    [[ -z "$cpu_time"  ]] && cpu_time="NaN"
    [[ -z "$mem_mb"    ]] && mem_mb="NaN"
    
    echo "$final_exit $wall_time $cpu_time $mem_mb"
}

# Calcula estatísticas (trimmed mean + std) de arquivo com valores
calculate_statistics() {
    local data_file="$1"
    local trim_percent="$2"
    
    local num_samples
    num_samples="$(grep -E '^[0-9eE+.\-]+$' "$data_file" | wc -l | awk '{print $1}')"
    
    if (( num_samples == 0 )); then
        echo "NaN NaN 0"
        return
    fi
    
    # Calcula quantos valores remover de cada extremo
    local trim_count start_idx end_idx
    trim_count="$(awk -v n="$num_samples" -v p="$trim_percent" 'BEGIN{ k=int(n*p/100.0); if(k<0)k=0; if(2*k>=n)k=int((n-1)/2); print k }')"
    start_idx=$((trim_count + 1))
    end_idx=$((num_samples - trim_count))
    
    if (( end_idx < start_idx )); then
        start_idx=1
        end_idx=1
    fi

    # Calcula média e desvio padrão dos valores trimados
    awk -v start="$start_idx" -v end="$end_idx" '
        function abs(x) { return x < 0 ? -x : x }
        BEGIN { count=0; sum=0.0; sum_squares=0.0 }
        /^[0-9eE+.\-]+$/ { values[++N] = $1 }
        END {
            if (N == 0) { print "NaN NaN 0"; exit }
            
            # Ordena valores (insertion sort)
            for (i=2; i<=N; i++) {
                x = values[i]
                j = i - 1
                while (j >= 1 && values[j] > x) {
                    values[j+1] = values[j]
                    j--
                }
                values[j+1] = x
            }
            
            # Valida índices
            if (start < 1) start = 1
            if (end > N) end = N
            
            # Calcula estatísticas dos valores trimados
            for (i=start; i<=end; i++) {
                v = values[i]
                count++
                sum += v
                sum_squares += v * v
            }
            
            if (count == 0) { print "NaN NaN 0"; exit }
            
            mean = sum / count
            
            if (count == 1) {
                std = 0.0
            } else {
                variance = (sum_squares - count * mean * mean) / (count - 1)
                if (variance < 0 && abs(variance) < 1e-18) variance = 0
                std = (variance < 0) ? 0 : sqrt(variance)
            }
            
            printf("%.9f %.9f %d\n", mean, std, count)
        }
    ' < "$data_file"
}

# Escreve cabeçalho do CSV de resultados
write_csv_header() {
    local csv_file="$1"
    if [[ ! -s "$csv_file" ]]; then
        echo "algorithm,operation,size,reps,trim_pct,trim_wall_s_raw,std_wall_s_raw,trim_cpu_s_raw,std_cpu_s_raw,trim_wall_s_base,std_wall_s_base,trim_cpu_s_base,std_cpu_s_base,net_wall_s,std_net_wall_s,net_cpu_s,std_net_cpu_s,trim_mem_mb,std_mem_mb,failures_raw,failures_base" > "$csv_file"
    fi
}

# Calcula composição de incerteza (quadratura) - "dois desviso padroões se acumulam"
calculate_quadrature_std() {
    local std_a="$1"
    local std_b="$2"
    
    if ! is_number "$std_a" || ! is_number "$std_b"; then
        echo "NaN"
        return
    fi
    
    awk -v a="$std_a" -v b="$std_b" 'BEGIN{ printf "%.9f", sqrt(a*a + b*b) }'
}

# Calcula diferença numérica
calculate_difference() {
    local value_a="$1"
    local value_b="$2"
    
    if ! is_number "$value_a" || ! is_number "$value_b"; then
        echo "NaN"
        return
    fi
    
    awk -v a="$value_a" -v b="$value_b" 'BEGIN{ printf "%.9f", (a - b) }'
}

# Coleta informações do sistema e salva em JSON
collect_system_info() {
    local output_json="$1"

    # Informações básicas do sistema
    local hostname kernel arch distro
    hostname="$(hostname 2>/dev/null || echo unknown)"
    kernel="$(uname -sr 2>/dev/null || echo unknown)"
    arch="$(uname -m 2>/dev/null || echo unknown)"
    distro="$( (source /etc/os-release 2>/dev/null && echo "${PRETTY_NAME}") || echo unknown )"

    # Informações da CPU
    local cpu_model cores_logical cores_physical threads_per_core
    local freq_min freq_max freq_current governor
    local cache_l1d cache_l1i cache_l2 cache_l3
    
    cpu_model="$(lscpu 2>/dev/null | awk -F: '/Model name/ {print $2}' | xargs)"
    [[ -z "$cpu_model" ]] && cpu_model="$(awk -F: '/model name/ {print $2; exit}' /proc/cpuinfo 2>/dev/null | xargs)"
    cores_logical="$(nproc 2>/dev/null || echo 0)"
    cores_physical="$(lscpu -p=Core,Socket 2>/dev/null | grep -v '^#' | sort -u | wc -l || echo 0)"
    threads_per_core="$(lscpu 2>/dev/null | awk -F: '/Thread\(s\)/ {print $2}' | sed 's/^ //')"
    freq_min="$(cat /sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_min_freq 2>/dev/null || echo 0)"
    freq_max="$(cat /sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq 2>/dev/null || echo 0)"
    freq_current="$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq 2>/dev/null || echo 0)"
    cache_l1d="$(lscpu | awk -F: '/L1d cache/ {print $2}' | sed 's/^ //')"
    cache_l1i="$(lscpu | awk -F: '/L1i cache/ {print $2}' | sed 's/^ //')"
    cache_l2="$(lscpu | awk -F: '/L2 cache/ {print $2}' | sed 's/^ //')"
    cache_l3="$(lscpu | awk -F: '/L3 cache/ {print $2}' | sed 's/^ //')"
    governor="$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo unknown)"

    # Informações de memória
    local mem_kb mem_gib swap_status
    mem_kb="$(awk '/MemTotal/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)"
    mem_gib="$(awk -v kb="${mem_kb:-0}" 'BEGIN{ printf "%.2f", (kb*1024)/1073741824.0 }')"
    swap_status="$(swapon --show 2>/dev/null | wc -l | awk '{print ($1==0) ? "disabled" : "enabled"}')"

    # Informações de armazenamento
    local fs_info storage_device storage_fs
    fs_info="$(findmnt -no SOURCE,FSTYPE,OPTIONS . 2>/dev/null || echo unknown)"
    storage_device="$(echo "$fs_info" | awk '{print $1}')"
    storage_fs="$(echo "$fs_info" | awk '{print $2}')"

    # Versões do toolchain
    local gcc_version clang_version cmake_version openssl_version
    gcc_version="$(gcc -dumpfullversion -dumpversion 2>/dev/null || echo unknown)"
    clang_version="$(clang --version 2>/dev/null | head -n1 || echo unknown)"
    cmake_version="$(cmake --version 2>/dev/null | head -n1 || echo unknown)"
    openssl_version="$(openssl version 2>/dev/null || echo unknown)"

    # Versões de liboqs e oqs-provider (fixas neste projeto)
    local liboqs_version="0.14.0"
    local oqsprovider_version="0.10.0"

    # Versão do runexec
    local runexec_version
    runexec_version="$(runexec --version 2>&1 | head -n1 || echo unknown)"

    # Label descritivo do sistema
    local system_label
    system_label="${cpu_model} | ${distro}"

    # Converte flag baseline para booleano JSON
    local baseline_bool
    baseline_bool=$([ "$BASELINE" -eq 1 ] && echo true || echo false)

    # Gera JSON
    cat > "$output_json" <<JSON
{
  "host": "$(json_escape "$hostname")",
  "kernel": "$(json_escape "$kernel")",
  "arch": "$(json_escape "$arch")",
  "distro": "$(json_escape "$distro")",
  "cpu": {
    "model": "$(json_escape "$cpu_model")",
    "cores_physical": $cores_physical,
    "cores_logical": $cores_logical,
    "threads_per_core": "$(json_escape "$threads_per_core")",
    "freq_min_khz": $freq_min,
    "freq_max_khz": $freq_max,
    "freq_current_khz": $freq_current,
    "cache_l1d": "$(json_escape "$cache_l1d")",
    "cache_l1i": "$(json_escape "$cache_l1i")",
    "cache_l2": "$(json_escape "$cache_l2")",
    "cache_l3": "$(json_escape "$cache_l3")",
    "governor": "$(json_escape "$governor")"
  },
  "memory": {
    "total_gib": $mem_gib,
    "swap": "$swap_status"
  },
  "storage": {
    "device": "$(json_escape "$storage_device")",
    "filesystem": "$(json_escape "$storage_fs")"
  },
  "toolchain": {
    "gcc": "$(json_escape "$gcc_version")",
    "clang": "$(json_escape "$clang_version")",
    "cmake": "$(json_escape "$cmake_version")",
    "openssl": "$(json_escape "$openssl_version")",
    "liboqs": "$liboqs_version",
    "oqs_provider": "$oqsprovider_version"
  },
  "runtime": {
    "benchexec": "$(json_escape "$runexec_version")",
    "environment": {
      "OPENSSL_CONF": "$(json_escape "${OPENSSL_CONF:-}")",
      "OPENSSL_MODULES": "$(json_escape "${OPENSSL_MODULES:-}")",
      "OSSL_PROVIDER_PATH": "$(json_escape "${OSSL_PROVIDER_PATH:-}")",
      "LD_LIBRARY_PATH": "$(json_escape "${LD_LIBRARY_PATH:-}")"
    }
  },
  "benchmark_config": {
    "algorithms": "$(json_escape "$ALGS")",
    "operations": "$(json_escape "$OPS")",
    "repetitions": $REPS,
    "message_sizes": "$(json_escape "$SIZES")",
    "trim_percent": $TRIM_PCT,
    "baseline_enabled": $baseline_bool,
    "output_dir": "$(json_escape "$OUTDIR")",
    "output_file": "$(json_escape "$OUTFILE")"
  },
  "runexec_options": {
    "timelimit": "$(json_escape "$TIMELIMIT")",
    "walltimelimit": "$(json_escape "$WALLTIMELIMIT")",
    "memlimit": "$(json_escape "$MEMLIMIT")",
    "cores": "$(json_escape "$CORES")"
  },
  "system_label": "$(json_escape "$system_label")",
  "timestamp_iso": "$(date -Iseconds)"
}
JSON

    echo "$system_label" > "${OUTDIR}/system_label.txt"
}

# Executa o benchmark completo
cmd_run() {
    # Valida binários
    check_binary "$WORKER"
    check_binary "$PREP"
    command -v runexec >/dev/null 2>&1 || fail "runexec não encontrado no PATH"
    
    # Valida parâmetros
    is_integer "$REPS" || fail "--reps deve ser inteiro"
    is_integer "$TRIM_PCT" || fail "--trim-pct deve ser inteiro"
    (( TRIM_PCT >= 0 && TRIM_PCT < 50 )) || fail "--trim-pct deve estar entre 0 e 49"

    # Cria diretório de saída (falha se já existir para evitar sobrescrever dados)
    if [[ -e "$OUTDIR" ]]; then
        fail "diretório de saída já existe: $OUTDIR (medida de segurança)"
    fi
    mkdir -p "$OUTDIR"

    # Coleta informações do sistema
    local system_json="${OUTDIR}/system_info.json"
    collect_system_info "$system_json"
    
    local result_csv="${OUTDIR}/${OUTFILE}"
    write_csv_header "$result_csv"

    # Converte listas em arrays
    csv_to_array "$ALGS"
    local -a algorithms_array=("${ARR[@]}")
    
    csv_to_array "$OPS"
    local -a operations_array=("${ARR[@]}")
    
    csv_to_array "$SIZES"
    local -a sizes_array=("${ARR[@]}")

    # Loop principal: algoritmos → operações → tamanhos → repetições
    for algorithm in "${algorithms_array[@]}"; do
        echo "[benchmark] Processando algoritmo: ${algorithm}"

        for operation in "${operations_array[@]}"; do
            # Define tamanhos a testar (keygen não depende de tamanho)
            local -a size_loop
            if [[ "$operation" == "keygen" ]]; then
                size_loop=("-")
            else
                size_loop=("${sizes_array[@]}")
            fi

            for msg_size in "${size_loop[@]}"; do
                # Arquivos temporários para coletar métricas
                local wall_file_raw cpu_file_raw mem_file_raw
                wall_file_raw="$(mktemp)"
                cpu_file_raw="$(mktemp)"
                mem_file_raw="$(mktemp)"
                
                local failures_raw=0
                local failures_baseline=0

                # Gera fixtures se necessário (sign/verify)
                local key_b64="" sig_b64=""
                if [[ "$operation" == "sign" || "$operation" == "verify" ]]; then
                    [[ "$msg_size" == "-" ]] && fail "BUG: tamanho não deveria ser '-' para $operation"
                    local fixture
                    fixture="$(generate_fixture "$algorithm" "$msg_size")"
                    key_b64="${fixture%%;*}"
                    sig_b64="${fixture#*;}"
                fi

                # Execuções RAW
                for ((rep=1; rep<=REPS; rep++)); do
                    local -a cmd_args
                    case "$operation" in
                        keygen)
                            cmd_args=( "$WORKER" keygen --alg "$algorithm" )
                            ;;
                        sign)
                            cmd_args=( "$WORKER" sign --key-b64 "$key_b64" --msg-len "$msg_size" )
                            ;;
                        verify)
                            cmd_args=( "$WORKER" verify --key-b64 "$key_b64" --sig-b64 "$sig_b64" --msg-len "$msg_size" )
                            ;;
                        all)
                            cmd_args=( "$WORKER" all --alg "$algorithm" --msg-len "$msg_size" )
                            ;;
                        *)
                            fail "operação inválida: $operation"
                            ;;
                    esac

                    read -r exit_code wall_time cpu_time mem_mb < <( run_single_benchmark "${cmd_args[@]}" )
                    
                    [[ "$exit_code" != "0" ]] && ((failures_raw++))
                    [[ "$wall_time" =~ ^[0-9] ]] && echo "$wall_time" >> "$wall_file_raw"
                    [[ "$cpu_time"  =~ ^[0-9] ]] && echo "$cpu_time"  >> "$cpu_file_raw"
                    [[ "$mem_mb"    =~ ^[0-9] ]] && echo "$mem_mb"    >> "$mem_file_raw"
                done

                # Execuções BASELINE (se habilitado)
                local wall_file_baseline cpu_file_baseline
                if [[ "$BASELINE" -eq 1 ]]; then
                    wall_file_baseline="$(mktemp)"
                    cpu_file_baseline="$(mktemp)"
                    
                    for ((rep=1; rep<=REPS; rep++)); do
                        local -a cmd_args_baseline
                        case "$operation" in
                            keygen)
                                cmd_args_baseline=( "$WORKER" keygen --alg "$algorithm" --baseline )
                                ;;
                            sign)
                                cmd_args_baseline=( "$WORKER" sign --key-b64 "$key_b64" --msg-len "$msg_size" --baseline )
                                ;;
                            verify)
                                cmd_args_baseline=( "$WORKER" verify --key-b64 "$key_b64" --sig-b64 "$sig_b64" --msg-len "$msg_size" --baseline )
                                ;;
                            all)
                                cmd_args_baseline=( "$WORKER" all --alg "$algorithm" --msg-len "$msg_size" --baseline )
                                ;;
                            *)
                                fail "operação inválida: $operation"
                                ;;
                        esac

                        read -r exit_code wall_time cpu_time _ < <( run_single_benchmark "${cmd_args_baseline[@]}" )
                        
                        [[ "$exit_code" != "0" ]] && ((failures_baseline++))
                        [[ "$wall_time" =~ ^[0-9] ]] && echo "$wall_time" >> "$wall_file_baseline"
                        [[ "$cpu_time"  =~ ^[0-9] ]] && echo "$cpu_time"  >> "$cpu_file_baseline"
                    done
                fi

                # Cálculo de estatísticas
                read -r mean_wall_raw std_wall_raw _ < <( calculate_statistics "$wall_file_raw" "$TRIM_PCT" )
                read -r mean_cpu_raw std_cpu_raw _ < <( calculate_statistics "$cpu_file_raw" "$TRIM_PCT" )
                read -r mean_mem std_mem _ < <( calculate_statistics "$mem_file_raw" "$TRIM_PCT" )

                local mean_wall_baseline std_wall_baseline mean_cpu_baseline std_cpu_baseline
                local net_wall std_net_wall net_cpu std_net_cpu
                
                if [[ "$BASELINE" -eq 1 ]]; then
                    read -r mean_wall_baseline std_wall_baseline _ < <( calculate_statistics "$wall_file_baseline" "$TRIM_PCT" )
                    read -r mean_cpu_baseline std_cpu_baseline _ < <( calculate_statistics "$cpu_file_baseline" "$TRIM_PCT" )
                    
                    # Calcula métricas NET (RAW - BASELINE)
                    net_wall="$(calculate_difference "$mean_wall_raw" "$mean_wall_baseline")"
                    net_cpu="$(calculate_difference "$mean_cpu_raw" "$mean_cpu_baseline")"
                    std_net_wall="$(calculate_quadrature_std "$std_wall_raw" "$std_wall_baseline")"
                    std_net_cpu="$(calculate_quadrature_std "$std_cpu_raw" "$std_cpu_baseline")"
                else
                    mean_wall_baseline="NaN"
                    std_wall_baseline="NaN"
                    mean_cpu_baseline="NaN"
                    std_cpu_baseline="NaN"
                    net_wall="NaN"
                    std_net_wall="NaN"
                    net_cpu="NaN"
                    std_net_cpu="NaN"
                fi

                # Escreve linha no CSV
                echo "${algorithm},${operation},${msg_size},${REPS},${TRIM_PCT},${mean_wall_raw},${std_wall_raw},${mean_cpu_raw},${std_cpu_raw},${mean_wall_baseline},${std_wall_baseline},${mean_cpu_baseline},${std_cpu_baseline},${net_wall},${std_net_wall},${net_cpu},${std_net_cpu},${mean_mem},${std_mem},${failures_raw},${failures_baseline}" >> "$result_csv"

                # Limpeza de temporários
                rm -f "$wall_file_raw" "$cpu_file_raw" "$mem_file_raw"
                if [[ "$BASELINE" -eq 1 ]]; then
                    rm -f "$wall_file_baseline" "$cpu_file_baseline"
                fi

                echo "[benchmark] ${algorithm}/${operation}/${msg_size} -> repetições=${REPS} falhas_raw=${failures_raw} falhas_baseline=${failures_baseline}"
            done
        done
    done

    echo "[benchmark] Informações do sistema: ${system_json}"
    echo "[benchmark] Resultados finais: ${result_csv}"
    echo "[benchmark] Concluído com sucesso."
}

# Parse de argumentos

# Verifica se há subcomando
if [[ $# -eq 0 ]]; then
    usage
    exit 0
fi

SUBCOMMAND="$1"
shift

case "$SUBCOMMAND" in
    list-algs)
        cmd_list_algs
        ;;
    run)
        # Parse de opções para 'run'
        while [[ $# -gt 0 ]]; do
            case "$1" in
                --algs)          ALGS="$2"; shift 2;;
                --ops)           OPS="$2"; shift 2;;
                --reps)          REPS="$2"; shift 2;;
                --sizes)         SIZES="$2"; shift 2;;
                --outdir)        OUTDIR="$2"; shift 2;;
                --outfile)       OUTFILE="$2"; shift 2;;
                --trim-pct)      TRIM_PCT="$2"; shift 2;;
                --baseline)      BASELINE=1; shift 1;;
                --timelimit)     TIMELIMIT="$2"; shift 2;;
                --walltimelimit) WALLTIMELIMIT="$2"; shift 2;;
                --memlimit)      MEMLIMIT="$2"; shift 2;;
                --cores)         CORES="$2"; shift 2;;
                -h|--help)       usage; exit 0;;
                *)               fail "opção desconhecida: $1";;
            esac
        done
        cmd_run
        ;;
    -h|--help)
        usage
        exit 0
        ;;
    *)
        fail "subcomando desconhecido: $SUBCOMMAND (use 'list-algs' ou 'run')"
        ;;
esac