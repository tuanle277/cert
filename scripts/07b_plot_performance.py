"""Generate performance figures from grid_run.jsonl: success rate with CI, exposure vs injection."""

import argparse
import os
import yaml
from collections import defaultdict

from cert_agent_exp.common.io import read_jsonl
from cert_agent_exp.eval import aggregate_success_rate, bootstrap, plot_performance_by_defense, plot_exposure_and_injection


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--bootstrap-seed", type=int, default=42)
    ap.add_argument("--bootstrap-n", type=int, default=1000)
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

    # Performance: success rate with bootstrap 95% CI
    defense_stats = {}
    for defense, run_logs in by_defense.items():
        rate = aggregate_success_rate(run_logs)
        if len(run_logs) >= 2:
            point, lower, upper = bootstrap(run_logs, aggregate_success_rate, n_bootstrap=args.bootstrap_n, seed=args.bootstrap_seed)
            defense_stats[defense] = {"rate": point, "lower": lower, "upper": upper, "n": len(run_logs)}
        else:
            defense_stats[defense] = {"rate": rate, "lower": rate, "upper": rate, "n": len(run_logs)}
        # Exposure stats from logs
        mean_exposed = sum(len(L.get("exposed_sources") or []) for L in run_logs) / max(1, len(run_logs))
        mean_injected = sum(len(L.get("injected_sources") or []) for L in run_logs) / max(1, len(run_logs))
        defense_stats[defense]["mean_exposed"] = mean_exposed
        defense_stats[defense]["mean_injected"] = mean_injected

    out1 = os.path.join(figures_dir, "performance_by_defense.png")
    plot_performance_by_defense(defense_stats, out_path=out1)
    print(f"[ok] performance -> {out1}")

    out2 = os.path.join(figures_dir, "exposure_and_injection.png")
    plot_exposure_and_injection(defense_stats, out_path=out2)
    print(f"[ok] exposure/injection -> {out2}")

    print("\nPerformance figures (use these for results/slides):")
    print("  runs/figures/performance_by_defense.png  — Task success rate by defense (95% CI)")
    print("  runs/figures/exposure_and_injection.png — Mean exposed vs injected sources by defense")


if __name__ == "__main__":
    main()
