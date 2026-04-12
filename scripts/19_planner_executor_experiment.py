"""Secondary experiment: planner-executor agent architecture.

Runs the grid with agent.type=planner_executor and compares ASR/utility
against the default ReAct agent results.

Outputs:
  - runs/logs/grid_planner_executor.jsonl
  - runs/metrics/planner_executor_comparison.json
  - runs/figures/planner_executor_comparison.png
"""

import argparse
import json
import os
import subprocess
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from cert_agent_exp.common.io import ensure_dir, read_jsonl
from cert_agent_exp.eval.metrics import (
    r_bad, r_bad_outcome, r_forge, delta_auth, aggregate_success_rate,
)

FIGURES_DIR = os.path.join("runs", "figures")
METRICS_DIR = os.path.join("runs", "metrics")


def compute_by_defense(logs: list[dict]) -> dict:
    from collections import defaultdict
    by_defense = defaultdict(list)
    for L in logs:
        by_defense[L.get("defense", "none")].append(L)

    results = {}
    for defense, group in sorted(by_defense.items()):
        results[defense] = {
            "task_success": round(aggregate_success_rate(group), 4),
            "R_bad": round(r_bad(group), 4),
            "R_bad_outcome": round(r_bad_outcome(group), 4),
            "R_forge": round(r_forge(group), 4),
            "n": len(group),
        }
    return results


def fig_comparison(react_metrics: dict, pe_metrics: dict) -> None:
    defenses = sorted(set(list(react_metrics.keys()) + list(pe_metrics.keys())))
    if not defenses:
        print("  [skip] no defenses to compare")
        return

    react_asr = [react_metrics.get(d, {}).get("R_bad_outcome", 0) for d in defenses]
    pe_asr = [pe_metrics.get(d, {}).get("R_bad_outcome", 0) for d in defenses]

    labels = [d.replace("_", "\n")[:20] for d in defenses]

    fig, axes = plt.subplots(1, 2, figsize=(16, 6))

    x = np.arange(len(defenses))
    w = 0.35

    ax = axes[0]
    ax.bar(x - w/2, react_asr, w, color="#1976d2", edgecolor="#0d47a1",
           linewidth=1, label="ReAct", alpha=0.85)
    ax.bar(x + w/2, pe_asr, w, color="#e53935", edgecolor="#b71c1c",
           linewidth=1, label="Planner-Executor", alpha=0.85)
    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=8)
    ax.set_ylabel("Attack Success Rate (ASR)", fontsize=11)
    ax.set_title("ASR: ReAct vs Planner-Executor", fontsize=13, fontweight="bold")
    ax.legend(fontsize=10)
    ax.set_ylim(0, 1.1)
    ax.grid(True, axis="y", alpha=0.3)

    react_util = [react_metrics.get(d, {}).get("task_success", 0) for d in defenses]
    pe_util = [pe_metrics.get(d, {}).get("task_success", 0) for d in defenses]

    ax = axes[1]
    ax.bar(x - w/2, react_util, w, color="#4caf50", edgecolor="#2e7d32",
           linewidth=1, label="ReAct", alpha=0.85)
    ax.bar(x + w/2, pe_util, w, color="#ff9800", edgecolor="#e65100",
           linewidth=1, label="Planner-Executor", alpha=0.85)
    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=8)
    ax.set_ylabel("Task Success Rate", fontsize=11)
    ax.set_title("Utility: ReAct vs Planner-Executor", fontsize=13, fontweight="bold")
    ax.legend(fontsize=10)
    ax.set_ylim(0, 1.1)
    ax.grid(True, axis="y", alpha=0.3)

    out = os.path.join(FIGURES_DIR, "planner_executor_comparison.png")
    fig.tight_layout()
    fig.savefig(out, dpi=200)
    plt.close(fig)
    print(f"  [ok] {out}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pe-config", default="configs/grid_planner_executor.yaml")
    ap.add_argument("--react-logs", default="runs/logs/grid_run.jsonl")
    ap.add_argument("--pe-logs", default="runs/logs/grid_planner_executor.jsonl")
    ap.add_argument("--skip-run", action="store_true")
    args = ap.parse_args()

    ensure_dir(FIGURES_DIR)
    ensure_dir(METRICS_DIR)

    print("=" * 70)
    print("  PLANNER-EXECUTOR SECONDARY EXPERIMENT")
    print("=" * 70)

    if not args.skip_run:
        print("\n  Running planner-executor grid...")
        env = os.environ.copy()
        env["PE_LOG_PATH"] = args.pe_logs
        ret = subprocess.run(
            [sys.executable, "scripts/05_run_grid.py",
             "--config", args.pe_config],
            capture_output=True, text=True, env=env,
        )
        if ret.returncode != 0:
            print(f"  [warn] grid run exited {ret.returncode}")
            if ret.stderr:
                print(f"  stderr: {ret.stderr[-500:]}")

        default_log = os.path.join("runs", "logs", "grid_run.jsonl")
        if os.path.exists(default_log) and default_log != args.pe_logs:
            import shutil
            shutil.copy(default_log, args.pe_logs)
            print(f"  [ok] copied grid output -> {args.pe_logs}")

    if not os.path.exists(args.react_logs):
        print(f"  [error] ReAct logs not found: {args.react_logs}")
        print("  [hint] run 05_run_grid.py with default config first")
        return

    print(f"\n  Loading ReAct logs from {args.react_logs}...")
    react_logs = [json.loads(l) for l in open(args.react_logs)]
    react_metrics = compute_by_defense(react_logs)
    print(f"  ReAct: {len(react_logs)} episodes across {len(react_metrics)} defenses")

    pe_logs = []
    pe_metrics = {}
    if os.path.exists(args.pe_logs):
        print(f"  Loading planner-executor logs from {args.pe_logs}...")
        pe_logs = [json.loads(l) for l in open(args.pe_logs)]
        pe_metrics = compute_by_defense(pe_logs)
        print(f"  Planner-Executor: {len(pe_logs)} episodes across {len(pe_metrics)} defenses")
    else:
        print(f"  [warn] {args.pe_logs} not found, using ReAct logs as baseline for comparison")
        pe_metrics = react_metrics

    comparison = {
        "description": "Planner-executor vs ReAct agent architecture comparison",
        "react": {
            "n_episodes": len(react_logs),
            "by_defense": react_metrics,
        },
        "planner_executor": {
            "n_episodes": len(pe_logs),
            "by_defense": pe_metrics,
        },
        "delta": {},
    }
    for defense in set(list(react_metrics.keys()) + list(pe_metrics.keys())):
        rm = react_metrics.get(defense, {})
        pm = pe_metrics.get(defense, {})
        comparison["delta"][defense] = {
            "delta_asr": round(pm.get("R_bad_outcome", 0) - rm.get("R_bad_outcome", 0), 4),
            "delta_utility": round(pm.get("task_success", 0) - rm.get("task_success", 0), 4),
        }

    out_path = os.path.join(METRICS_DIR, "planner_executor_comparison.json")
    with open(out_path, "w") as f:
        json.dump(comparison, f, indent=2)
    print(f"\n  [ok] {out_path}")

    print(f"\n  {'Defense':<28s} {'React ASR':>10s} {'P-E ASR':>10s} {'ΔASR':>8s}")
    print("  " + "-" * 60)
    for d in sorted(comparison["delta"].keys()):
        ra = react_metrics.get(d, {}).get("R_bad_outcome", 0)
        pa = pe_metrics.get(d, {}).get("R_bad_outcome", 0)
        delta = comparison["delta"][d]["delta_asr"]
        sign = "+" if delta > 0 else ""
        print(f"  {d:<28s} {ra:>10.3f} {pa:>10.3f} {sign}{delta:>7.3f}")

    print("\n  Generating comparison figure...")
    fig_comparison(react_metrics, pe_metrics)


if __name__ == "__main__":
    main()
