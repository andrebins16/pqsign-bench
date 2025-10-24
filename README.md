# PQSig-Bench

Plataforma de benchmark para algoritmos de assinatura digital pós-quânticos usando C, liboqs, oqs-provider, OpenSSL e BenchExec.

## Visão Geral

Este repositório compila e executa benchmarks de algoritmos de assinatura digital (+100), incluindo:
- **Algoritmos pós-quânticos**: ML-DSA, Falcon, SPHINCS+, além de diversos outros
- **Algoritmos clássicos**: RSA, ECDSA

### Componentes Principais

- **crypto_core** — Contém todas as primitivas criptográficas necessárias, assim como integrações com as bibliotecas criptográficas
- **bench_worker** — Executa operações criptográficas (keygen/sign/verify/all) para medição
- **bench_prep** — Utilitário para gerar chaves e assinaturas em Base64 fora da medição
- **run_bench.sh** — Orquestra benchmarks usando BenchExec/runexec
- **plot.py** — Gera gráficos dos resultados

## Requisitos

### Sistema Operacionais Suportados
- Ubuntu 24.04+ (host x86_64)
- Raspberry Pi OS (para Raspberry Pi 3B)

### Dependências
- Python 3.10+
- OpenSSL 3.x (do sistema)

# 1. Setup Inicial

## Ubuntu (x86_64)
### Instala dependências base e realiza configurações
./scripts/ubuntu_00_setup_deps.sh

### Instala dependências externas 
./scripts/ubuntu_01_fetch_thirdparty.sh

### Compila tudo (liboqs, oqs-provider, aplicação)
./scripts/ubuntu_02_build.sh


## Raspberry Pi 3B
### Instala dependências base e realiza configurações
./scripts/pi_00_setup_deps.sh

### Instala dependências externas, confirma instalação de dependências base e configurações 
./scripts/pi_01_fetch_thirdparty.sh

### Compila tudo (liboqs, oqs-provider, aplicação)
./scripts/pi_02_build.sh


# 2. Uso Básico

## Configurar CPU para Benchmarking (Recomendado)

Antes de executar benchmarks, configure a CPU para modo performance para reduzir variabilidade nos resultados e garantir reprodutibilidade:
```
# Executar UMA VEZ antes dos benchmarks (requer sudo)
sudo ./scripts/setup_cpu_performance.sh
```

## Opções do run_bench.sh:
```
Uso: ./src/scripts/run_bench.sh SUBCOMANDO [opções]

Subcomandos:
  list-algs              Lista todos os algoritmos de assinatura disponíveis
  run                    Executa benchmark

Opções para 'run':
  --algs "LISTA"         Algoritmos separados por vírgula (entre aspas)
                         (default: RSA,EC,família SPHINCS,família ML-DSA,família Falcon)
  --ops "LISTA"          Operações separadas por vírgula (entre aspas)
                         Opções: keygen,sign,verify,all
                         (default: "keygen,sign,verify,all")
  --reps N               Número de repetições (default: 100)
  --sizes "LISTA"        Tamanhos de mensagem em bytes, separados por vírgula (entre aspas)
                         (default: "256,100000,100000000" = 256 bytes, 100KB, 100MB)
  --outdir DIR           Diretório de saída (default: $"${ROOT}/results")
  --outfile NOME.csv     Nome do arquivo CSV (default: results.csv)
  --trim-pct P           Percentual de trim para estatística (default: 15)
  --baseline             Ativa medição de baseline para calcular overhead
                         (default: desabilitado) Recomendado ativar.

  Opções do runexec:
  --timelimit VAL        Limite de tempo de CPU em segundos (default: 5s)
  --walltimelimit VAL    Limite de tempo de parede em segundos (default: 6s)
  --memlimit VAL         Limite de memória em bytes (default: 500000000 = 500MB)
  --cores "LISTA"        Lista de cores a usar (entre aspas se múltiplos)
                         Ex: 0 ou "0,2-3" (default: "0")

  -h|--help              Mostra esta ajuda

Nota: Para passar listas com múltiplos valores, use aspas duplas e separe por vírgula.
      Exemplo: --algs "mldsa44,falcon512,RSA"
```

## Listar Algoritmos Disponíveis

### Via script de benchmark
./src/scripts/run_bench.sh list-algs

## Executar Benchmark

### Benchmark default (todos algoritmos, 100 repetições)
./src/scripts/run_bench.sh run

### Apenas alguns algoritmos, 50 repetições
./src/scripts/run_bench.sh run --algs "mldsa44,falcon512,RSA" --reps 50

### Com baseline (mede overhead do framework)
./src/scripts/run_bench.sh run --algs mldsa44 --baseline --reps 100

### Personalizando tamanhos de mensagem
./src/scripts/run_bench.sh run --sizes "1000,10000,100000" --reps 50

### Personalizado com parametros para o benchexec
./src/scripts/run_bench.sh run \
  --algs sphincssha2128fsimple \
  --reps 50 \
  --timelimit 30 \
  --walltimelimit 35 \
  --memlimit 268435456 \
  --cores 0

# 3. Resultados

## Estrutura do Diretório de Saída

Após executar `./scripts/run_bench.sh run`, os resultados ficam em:
```
results/
├── results.csv           # Dados brutos do benchmark
├── system_info.json      # Informações do hardware/sistema/run
└── system_label.txt      # Label descritivo do sistema
```
Formato do CSV
O results.csv contém as métricas de cada execução:

Identificação: algorithm, operation, size, reps, trim_pct

Métricas RAW: trim_wall_s_raw, std_wall_s_raw, trim_cpu_s_raw, std_cpu_s_raw, trim_mem_mb, std_mem_mb

Métricas BASELINE (se --baseline): trim_wall_s_base, std_wall_s_base, trim_cpu_s_base, std_cpu_s_base

Métricas NET (RAW - BASELINE): net_wall_s, std_net_wall_s, net_cpu_s, std_net_cpu_s

RAW: medição completa (primitiva + overhead)

BASE: medição apenas do overhead (com --baseline)

NET: tempo líquido das primitivas (RAW - BASE)


# 4. Visualização de Resultados

## Gerar Gráficos

### Gera gráficos a partir dos resultados
python3 src/plot.py resultsdir --env-name <nomeAmbiente>

### Estrutura de Saída
Após a execução, o script gera dois conjuntos de saídas dentro do diretório de resultados (results_dir):

```
results_dir/
├── plots/
│   ├── wall_raw/
│   ├── cpu_raw/
│   ├── mem_raw/
│   ├── wall_base/      # Se usou --baseline
│   ├── cpu_base/       # Se usou --baseline
|   ├── mem_base/       # Se usou --baseline
│   ├── wall_net/       # Se usou --baseline
|   ├── cpu_net/        # Se usou --baseline
│   └── mem_net/        # Se usou --baseline
│
└── subTables/
    ├── wall_raw/
    ├── cpu_raw/
    ├── mem_raw/
    ├── wall_base/      # Se usou --baseline
    ├── cpu_base/       # Se usou --baseline
    ├── mem_base/       # Se usou --baseline    
    ├── wall_net/       # Se usou --baseline
    ├── cpu_net/       # Se usou --baseline
    └── mem_net/        # Se usou --baseline
```

## Conteúdo Gerado
### Gráficos (plots/)
Cada subdiretório contém gráficos em formato .png organizados por tipo de métrica, operação e tamanho de mensagem.
Os títulos e eixos são automaticamente gerados em português, e cada gráfico inclui barras de erro com o desvio padrão.

### Subtabelas (subTables/)
Para cada gráfico gerado, é criado um arquivo .csv correspondente contendo apenas os dados daquele gráfico.


# 5. Reprodução dos Experimentos do Artigo

Os comandos abaixo reproduzem exatamente os experimentos apresentados no trabalho.

### Ubuntu local:
./scripts/ubuntu_00_setup_deps.sh

./scripts/ubuntu_01_fetch_thirdparty.sh

./scripts/ubuntu_02_build.sh

sudo ./scripts/setup_cpu_performance.sh

src/scripts/run_bench.sh run --baseline --outdir FINALRESULTSUBUNTU

python3 src/plot.py FINALRESULTSUBUNTU --env-name "Notebook Ubuntu"

### Raspberry Pi 3B:
./scripts/pi_00_setup_deps.sh

./scripts/pi_01_fetch_thirdparty.sh

./scripts/pi_02_build.sh

sudo ./scripts/setup_cpu_performance.sh

src/scripts/run_bench.sh run --baseline --outdir FINALRESULTSBERRYPI --timelimit 35 --walltimelimit 36

python src/plot.py FINALRESULTSBERRYPI --env-name "Raspberry Pi 3B"
