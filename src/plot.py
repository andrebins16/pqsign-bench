#!/usr/bin/env python3
import argparse
import os
import pandas as pd
import matplotlib.pyplot as plt
from collections import OrderedDict

def coerce_numeric(df, cols):
    for c in cols:
        if c in df.columns:
            df[c] = pd.to_numeric(df[c], errors="coerce")
    return df

def ensure_dirs(base_dir, groups):
    os.makedirs(base_dir, exist_ok=True)
    for group in groups:
        os.makedirs(os.path.join(base_dir, group), exist_ok=True)

def ensure_subtables_dirs(base_dir, groups):
    os.makedirs(base_dir, exist_ok=True)
    for group in groups:
        os.makedirs(os.path.join(base_dir, group), exist_ok=True)

def order_by_first_occurrence(values):
    return list(OrderedDict.fromkeys(values))

def load_system_label(results_dir):
    """Carrega o system label do arquivo system_label.txt"""
    label_path = os.path.join(results_dir, "system_label.txt")
    if os.path.isfile(label_path):
        with open(label_path, 'r') as f:
            return f.read().strip()
    return None

def get_operation_title(op, size):
    """Retorna título em português para a operação"""
    op_names = {
        "keygen": "Geração de Chaves",
        "sign": "Assinatura",
        "verify": "Verificação",
        "all": "Ciclo Completo"
    }
    base_title = op_names.get(op, op)
    
    if size == "-":
        return base_title
    else:
        # Converte tamanho para formato legível (ex: 1000000 -> 1MB)
        try:
            size_bytes = int(size)
            if size_bytes >= 1_000_000:
                size_str = f"{size_bytes // 1_000_000}MB"
            elif size_bytes >= 1_000:
                size_str = f"{size_bytes // 1_000}KB"
            else:
                size_str = f"{size_bytes}B"
        except:
            size_str = size
        
        return f"{base_title} — Mensagem de {size_str}"

def get_metric_suffix(metric_type):
    suffixes = {
        "raw_wall": "Tempo Total de Parede",
        "raw_cpu": "Tempo Total de CPU",
        "base_wall": "Overhead de Tempo de Parede",
        "base_cpu": "Overhead de Tempo de CPU",
        "net_wall": "Tempo Líquido de Parede",
        "net_cpu": "Tempo Líquido de CPU",
        "mem": "Pico de Memória"
    }
    return suffixes.get(metric_type, "")

def plot_hbar(sub_df, value_col, err_col, ylabel_col, title, xlabel, out_path, system_label=None):
    if sub_df.empty or value_col not in sub_df.columns:
        return
    # se todas as linhas são NaN, não plota
    vals = sub_df[value_col]
    if vals.isna().all():
        return

    # ordem de algoritmos pela primeira ocorrência 
    first_idx = sub_df.groupby(ylabel_col).apply(lambda s: s.index.min()).sort_values()
    alg_order = list(first_idx.index)[::-1]
    sub_df = sub_df.copy()
    sub_df[ylabel_col] = pd.Categorical(sub_df[ylabel_col], categories=alg_order, ordered=True)
    sub_df = sub_df.sort_values(ylabel_col)

    y = range(len(sub_df))
    errs = sub_df[err_col].fillna(0.0).values if err_col in sub_df.columns else [0.0] * len(sub_df)

    fig, ax = plt.subplots(figsize=(10, max(6, len(sub_df) * 0.3)))
    ax.barh(list(y), sub_df[value_col].values, xerr=errs, capsize=4)
    ax.set_yticks(list(y))
    ax.set_yticklabels(sub_df[ylabel_col].tolist())
    ax.set_xlabel(xlabel)
    ax.set_title(title, fontsize=12, fontweight='bold', pad=20)
    
    # System label discreto abaixo do título, centralizado
    if system_label:
        ax.text(0.5, 1.02, system_label, 
                transform=ax.transAxes,
                fontsize=8,
                style='italic',
                verticalalignment='bottom',
                horizontalalignment='center',
                color='gray')
    
    plt.tight_layout()
    plt.savefig(out_path, dpi=150)
    plt.close()
    print(f"salvo: {out_path}")

def write_subtable_csv(sub_df, alg_col, value_col, err_col, out_csv_path):
    """Salva apenas as colunas usadas no gráfico: algorithm, value, std"""
    if sub_df.empty or value_col not in sub_df.columns:
        return
    vals = sub_df[value_col]
    if vals.isna().all():
        return
    out_dir = os.path.dirname(out_csv_path)
    os.makedirs(out_dir, exist_ok=True)
    tbl = pd.DataFrame({
        "algorithm": sub_df[alg_col].astype(str).values,
        "value": sub_df[value_col].values,
        "std": sub_df[err_col].fillna(0.0).values if err_col in sub_df.columns else [0.0]*len(sub_df)
    })
    tbl.to_csv(out_csv_path, index=False)
    print(f"salvo: {out_csv_path}")

def main():
    ap = argparse.ArgumentParser(description="Plota resultados do benchmark (RAW, opcional BASELINE/NET) a partir do CSV consolidado.")
    ap.add_argument("results_dir", help="Diretório contendo results.csv")
    ap.add_argument("--drop-failed", action="store_true",
                    help="Descarta linhas com failures_raw > 0 ou failures_base > 0")
    ap.add_argument("--time-unit", choices=["s", "ms"], default="ms",
                    help="Unidade para tempos (default: ms)")
    args = ap.parse_args()

    # Monta o path do CSV: results_dir/results.csv
    csv_path = os.path.join(args.results_dir, "results.csv")
    if not os.path.isfile(csv_path):
        print(f"ERRO: arquivo não encontrado: {csv_path}")
        return 1

    df = pd.read_csv(csv_path)

    # Carrega system label
    system_label = load_system_label(args.results_dir)
    if system_label:
        print(f"System label: {system_label}")

    # Sempre salva em <results_dir>/plots e subtabelas em <results_dir>/plots/subTables
    outdir = os.path.join(os.path.normpath(args.results_dir), "plots")
    subtables_base = os.path.join(os.path.normpath(args.results_dir), "subTables")

    # Normaliza tipos
    df["algorithm"] = df["algorithm"].astype(str)
    df["operation"] = df["operation"].astype(str)
    df["size"] = df["size"].astype(str)  # pode ser '-' para keygen

    df = coerce_numeric(df, [
        "reps","trim_pct",
        # RAW
        "trim_wall_s_raw","std_wall_s_raw",
        "trim_cpu_s_raw","std_cpu_s_raw",
        # BASE
        "trim_wall_s_base","std_wall_s_base",
        "trim_cpu_s_base","std_cpu_s_base",
        # NET
        "net_wall_s","std_net_wall_s",
        "net_cpu_s","std_net_cpu_s",
        # MEM (RAW)
        "trim_mem_mb","std_mem_mb",
        # FAILS
        "failures_raw","failures_base"
    ])

    # Opcional: remove combinações com falhas (raw e base, se existirem)
    if args.drop_failed:
        cond = (df["failures_raw"] == 0)
        if "failures_base" in df.columns:
            cond = cond & (df["failures_base"] == 0)
        df = df[cond].copy()

    # Conversão de unidade para tempos
    t_factor = 1.0
    t_label = "s"
    if args.time_unit == "ms":
        t_factor = 1000.0
        t_label = "ms"

    # Derivados para plot (RAW)
    df["wall_raw_val"] = df["trim_wall_s_raw"] * t_factor
    df["wall_raw_err"] = df["std_wall_s_raw"]  * t_factor
    df["cpu_raw_val"]  = df["trim_cpu_s_raw"]  * t_factor
    df["cpu_raw_err"]  = df["std_cpu_s_raw"]   * t_factor

    # BASE/NET podem ser todos NaN quando baseline não foi rodado
    has_base = False
    has_net = False
    if "trim_wall_s_base" in df.columns or "trim_cpu_s_base" in df.columns:
        has_base = (df.get("trim_wall_s_base", pd.Series(dtype=float)).notna().any() or
                    df.get("trim_cpu_s_base", pd.Series(dtype=float)).notna().any())
    if "net_wall_s" in df.columns or "net_cpu_s" in df.columns:
        has_net = (df.get("net_wall_s", pd.Series(dtype=float)).notna().any() or
                   df.get("net_cpu_s", pd.Series(dtype=float)).notna().any())

    if has_base:
        df["wall_base_val"] = df["trim_wall_s_base"] * t_factor
        df["wall_base_err"] = df["std_wall_s_base"]  * t_factor
        df["cpu_base_val"]  = df["trim_cpu_s_base"]  * t_factor
        df["cpu_base_err"]  = df["std_cpu_s_base"]   * t_factor

    if has_net:
        df["wall_net_val"] = df["net_wall_s"] * t_factor
        df["wall_net_err"] = df["std_net_wall_s"] * t_factor
        df["cpu_net_val"]  = df["net_cpu_s"]  * t_factor
        df["cpu_net_err"]  = df["std_net_cpu_s"]  * t_factor

    # Diretórios: criamos apenas o necessário
    groups = ["wall_raw", "cpu_raw", "mem_raw"]
    if has_base:
        groups += ["wall_base", "cpu_base"]
    if has_net:
        groups += ["wall_net", "cpu_net"]
    ensure_dirs(outdir, groups)
    ensure_subtables_dirs(subtables_base, groups)

    # Ordem das operações
    ops_order = ["keygen", "sign", "verify", "all"]
    df["operation"] = pd.Categorical(df["operation"], categories=ops_order, ordered=True)
    df = df.sort_values(["operation", "size"])

    # Para cada operação, plota por size (para keygen, size == "-")
    for op in df["operation"].cat.categories:
        sub_op = df[df["operation"] == op]
        if sub_op.empty:
            continue

        # mantém ordem de aparição de size
        sizes_order = order_by_first_occurrence(sub_op["size"].tolist())
        for size in sizes_order:
            sub = sub_op[sub_op["size"] == size].copy()
            if sub.empty:
                continue

            # Título base em português
            title_base = get_operation_title(op, size)

            # WALL RAW
            group = "wall_raw"
            out_path = os.path.join(outdir, group, f"bench_{op}_{size}_{group}.png")
            sub_for_plot = sub.rename(columns={"algorithm": "alg"})
            plot_hbar(
                sub_df=sub_for_plot,
                value_col="wall_raw_val",
                err_col="wall_raw_err",
                ylabel_col="alg",
                title=f"{title_base} — {get_metric_suffix('raw_wall')}",
                xlabel=f"Tempo ({t_label})",
                out_path=out_path,
                system_label=system_label
            )
            # subtable
            out_csv = os.path.join(subtables_base, group, f"bench_{op}_{size}_{group}.csv")
            write_subtable_csv(sub_for_plot, "alg", "wall_raw_val", "wall_raw_err", out_csv)

            # WALL BASE (se existir)
            if has_base:
                group = "wall_base"
                out_path = os.path.join(outdir, group, f"bench_{op}_{size}_{group}.png")
                plot_hbar(
                    sub_df=sub_for_plot,
                    value_col="wall_base_val",
                    err_col="wall_base_err",
                    ylabel_col="alg",
                    title=f"{title_base} — {get_metric_suffix('base_wall')}",
                    xlabel=f"Tempo ({t_label})",
                    out_path=out_path,
                    system_label=system_label
                )
                out_csv = os.path.join(subtables_base, group, f"bench_{op}_{size}_{group}.csv")
                write_subtable_csv(sub_for_plot, "alg", "wall_base_val", "wall_base_err", out_csv)

            # WALL NET (se existir)
            if has_net:
                group = "wall_net"
                out_path = os.path.join(outdir, group, f"bench_{op}_{size}_{group}.png")
                plot_hbar(
                    sub_df=sub_for_plot,
                    value_col="wall_net_val",
                    err_col="wall_net_err",
                    ylabel_col="alg",
                    title=f"{title_base} — {get_metric_suffix('net_wall')}",
                    xlabel=f"Tempo ({t_label})",
                    out_path=out_path,
                    system_label=system_label
                )
                out_csv = os.path.join(subtables_base, group, f"bench_{op}_{size}_{group}.csv")
                write_subtable_csv(sub_for_plot, "alg", "wall_net_val", "wall_net_err", out_csv)

            # CPU RAW
            group = "cpu_raw"
            out_path = os.path.join(outdir, group, f"bench_{op}_{size}_{group}.png")
            plot_hbar(
                sub_df=sub_for_plot,
                value_col="cpu_raw_val",
                err_col="cpu_raw_err",
                ylabel_col="alg",
                title=f"{title_base} — {get_metric_suffix('raw_cpu')}",
                xlabel=f"Tempo ({t_label})",
                out_path=out_path,
                system_label=system_label
            )
            out_csv = os.path.join(subtables_base, group, f"bench_{op}_{size}_{group}.csv")
            write_subtable_csv(sub_for_plot, "alg", "cpu_raw_val", "cpu_raw_err", out_csv)

            # CPU BASE (se existir)
            if has_base:
                group = "cpu_base"
                out_path = os.path.join(outdir, group, f"bench_{op}_{size}_{group}.png")
                plot_hbar(
                    sub_df=sub_for_plot,
                    value_col="cpu_base_val",
                    err_col="cpu_base_err",
                    ylabel_col="alg",
                    title=f"{title_base} — {get_metric_suffix('base_cpu')}",
                    xlabel=f"Tempo ({t_label})",
                    out_path=out_path,
                    system_label=system_label
                )
                out_csv = os.path.join(subtables_base, group, f"bench_{op}_{size}_{group}.csv")
                write_subtable_csv(sub_for_plot, "alg", "cpu_base_val", "cpu_base_err", out_csv)

            # CPU NET (se existir)
            if has_net:
                group = "cpu_net"
                out_path = os.path.join(outdir, group, f"bench_{op}_{size}_{group}.png")
                plot_hbar(
                    sub_df=sub_for_plot,
                    value_col="cpu_net_val",
                    err_col="cpu_net_err",
                    ylabel_col="alg",
                    title=f"{title_base} — {get_metric_suffix('net_cpu')}",
                    xlabel=f"Tempo ({t_label})",
                    out_path=out_path,
                    system_label=system_label
                )
                out_csv = os.path.join(subtables_base, group, f"bench_{op}_{size}_{group}.csv")
                write_subtable_csv(sub_for_plot, "alg", "cpu_net_val", "cpu_net_err", out_csv)

            # MEM (RAW)
            group = "mem_raw"
            out_path = os.path.join(outdir, group, f"bench_{op}_{size}_{group}.png")
            plot_hbar(
                sub_df=sub_for_plot,
                value_col="trim_mem_mb",
                err_col="std_mem_mb",
                ylabel_col="alg",
                title=f"{title_base} — {get_metric_suffix('mem')}",
                xlabel="Memória (MB)",
                out_path=out_path,
                system_label=system_label
            )
            out_csv = os.path.join(subtables_base, group, f"bench_{op}_{size}_{group}.csv")
            write_subtable_csv(sub_for_plot, "alg", "trim_mem_mb", "std_mem_mb", out_csv)

    return 0

if __name__ == "__main__":
    exit(main())
