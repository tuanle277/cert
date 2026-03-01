"""Plot success-rate frontiers and bar chart by defense."""

import argparse
import os
import yaml
from collections import defaultdict

from cert_agent_exp.common.io import read_jsonl
from cert_agent_exp.eval import aggregate_success_rate, plot_frontiers, plot_success_by_defense


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    args = ap.parse_args()

    cfg = yaml.safe_load(open(args.config, "r"))
    runs_dir = cfg.get("runs_dir", "runs")
    log_path = os.path.join(runs_dir, "logs", "grid_run.jsonl")
    figures_dir = os.path.join(runs_dir, "figures")
    os.makedirs(figures_dir, exist_ok=True)

    if not os.path.exists(log_path):
        print(f"[err] {log_path} not found; run 05_run_grid first")
        return

    logs = list(read_jsonl(log_path))
    by_defense = defaultdict(list)
    for L in logs:
        by_defense[L.get("defense", "none")].append(L)

    metrics_by_config = {
        def_name: [aggregate_success_rate(run_logs)]
        for def_name, run_logs in by_defense.items()
    }
    out_path = os.path.join(figures_dir, "frontier.png")
    plot_frontiers(metrics_by_config, x_label="defense", out_path=out_path)
    print(f"[ok] figure -> {out_path}")

    defense_rates = {d: aggregate_success_rate(run_logs) for d, run_logs in by_defense.items()}
    bar_path = os.path.join(figures_dir, "success_by_defense.png")
    plot_success_by_defense(defense_rates, out_path=bar_path)
    print(f"[ok] figure -> {bar_path}")


if __name__ == "__main__":
    main()
