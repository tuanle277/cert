"""Compute metrics from grid run logs: R_bad, task success, exposure rate, and by-defense breakdown."""

import argparse
import json
import os
import yaml
from collections import defaultdict

from cert_agent_exp.common.io import ensure_dir, read_jsonl, write_jsonl
from cert_agent_exp.eval import aggregate_success_rate, r_bad, exposure_rate


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    args = ap.parse_args()

    cfg = yaml.safe_load(open(args.config, "r"))
    runs_dir = cfg.get("runs_dir", "runs")
    log_path = os.path.join(runs_dir, "logs", "grid_run.jsonl")
    metrics_dir = os.path.join(runs_dir, "metrics")
    ensure_dir(metrics_dir)

    if not os.path.exists(log_path):
        print(f"[err] {log_path} not found; run 05_run_grid first")
        return

    logs = list(read_jsonl(log_path))

    # Overall baseline metrics (all runs)
    task_success = aggregate_success_rate(logs)
    R_bad_val = r_bad(logs)
    exp_rate = exposure_rate(logs)
    baseline = {
        "task_success": task_success,
        "R_bad": R_bad_val,
        "exposure_rate": exp_rate,
        "n": len(logs),
    }
    baseline_path = os.path.join(metrics_dir, "baseline.json")
    with open(baseline_path, "w", encoding="utf-8") as f:
        json.dump(baseline, f, indent=2)
    print(f"[ok] baseline metrics -> {baseline_path}")
    print(f"  task_success={task_success:.3f}  R_bad={R_bad_val:.3f}  exposure_rate={exp_rate:.3f}  n={len(logs)}")

    # By defense
    by_defense = defaultdict(list)
    for L in logs:
        by_defense[L.get("defense", "none")].append(L)

    metrics = []
    for defense, run_logs in by_defense.items():
        rate = aggregate_success_rate(run_logs)
        rb = r_bad(run_logs)
        er = exposure_rate(run_logs)
        metrics.append({
            "defense": defense,
            "success_rate": rate,
            "R_bad": rb,
            "exposure_rate": er,
            "n": len(run_logs),
        })

    out_path = os.path.join(metrics_dir, "by_defense.jsonl")
    write_jsonl(out_path, metrics)
    print(f"[ok] wrote by-defense metrics -> {out_path}")
    for m in metrics:
        print(f"  {m['defense']}: success_rate={m['success_rate']:.3f} R_bad={m['R_bad']:.3f} exposure_rate={m['exposure_rate']:.3f} n={m['n']}")


if __name__ == "__main__":
    main()
