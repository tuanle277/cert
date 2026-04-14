"""Performance plots from grid logs: ASR by defense (bootstrap CI), exposure, security."""

import argparse
import os
import sys
from collections import defaultdict

import yaml

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from cert_agent_exp.common.io import ensure_dir, read_jsonl
from cert_agent_exp.eval.bootstrap import bootstrap
from cert_agent_exp.eval.metrics import is_bad_outcome, r_bad, r_bad_outcome
from cert_agent_exp.eval.plots import (
    plot_exposure_and_injection,
    plot_performance_by_defense,
    plot_security_by_defense,
)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    args = ap.parse_args()

    cfg = yaml.safe_load(open(args.config, "r"))
    runs_dir = cfg.get("runs_dir", "runs")
    log_path = os.path.join(runs_dir, "logs", "grid_run.jsonl")
    fig_dir = os.path.join(runs_dir, "figures")
    ensure_dir(fig_dir)

    if not os.path.exists(log_path):
        print(f"[err] {log_path} not found; run 05_run_grid first")
        return

    logs = list(read_jsonl(log_path))
    by_defense: dict[str, list[dict]] = defaultdict(list)
    for L in logs:
        by_defense[L.get("defense", "none")].append(L)

    defense_stats: dict[str, dict] = {}
    exposure_stats: dict[str, dict] = {}
    security_metrics: dict[str, dict] = {}

    for defense, group in sorted(by_defense.items()):
        n = len(group)
        if n == 0:
            continue

        def asr_stat(sample: list[dict]) -> float:
            if not sample:
                return 0.0
            return sum(1 for L in sample if is_bad_outcome(L)) / len(sample)

        rate, lo, hi = bootstrap(group, asr_stat, n_bootstrap=1000, seed=0)
        defense_stats[defense] = {
            "rate": rate,
            "lower": lo,
            "upper": hi,
            "n": n,
        }

        exposed_counts = []
        injected_counts = []
        for L in group:
            exp = L.get("exposed_sources") or []
            inj = L.get("injected_sources") or []
            exposed_counts.append(len(exp))
            injected_counts.append(len(inj))
        exposure_stats[defense] = {
            "mean_exposed": sum(exposed_counts) / max(1, len(exposed_counts)),
            "mean_injected": sum(injected_counts) / max(1, len(injected_counts)),
        }

        security_metrics[defense] = {
            "R_bad": r_bad(group),
            "R_bad_outcome": r_bad_outcome(group),
            "n": n,
        }

    plot_performance_by_defense(
        defense_stats,
        out_path=os.path.join(fig_dir, "performance_by_defense.png"),
    )
    plot_exposure_and_injection(
        exposure_stats,
        out_path=os.path.join(fig_dir, "exposure_and_injection.png"),
    )
    plot_security_by_defense(
        security_metrics,
        out_path=os.path.join(fig_dir, "security_by_defense.png"),
    )
    print(f"[ok] performance plots -> {fig_dir}/")
    print(f"      performance_by_defense.png, exposure_and_injection.png, security_by_defense.png")


if __name__ == "__main__":
    main()
