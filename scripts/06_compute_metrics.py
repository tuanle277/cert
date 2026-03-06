"""Compute metrics from grid run logs: R_bad, R_forge, task success, exposure rate, and by-defense breakdown."""

import argparse
import json
import os
import yaml
from collections import defaultdict

from cert_agent_exp.common.io import ensure_dir, read_jsonl, write_jsonl
from cert_agent_exp.eval import aggregate_success_rate, r_bad, r_bad_outcome, r_forge, delta_auth, exposure_rate


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
    R_bad_out_val = r_bad_outcome(logs)
    R_forge_val = r_forge(logs)
    delta_auth_val = delta_auth(logs)
    exp_rate = exposure_rate(logs)
    baseline = {
        "task_success": task_success,
        "R_bad": R_bad_val,
        "R_bad_outcome": R_bad_out_val,
        "R_forge": R_forge_val,
        "Delta_auth": delta_auth_val,
        "exposure_rate": exp_rate,
        "n": len(logs),
    }
    baseline_path = os.path.join(metrics_dir, "baseline.json")
    with open(baseline_path, "w", encoding="utf-8") as f:
        json.dump(baseline, f, indent=2)
    print(f"[ok] baseline metrics -> {baseline_path}")
    print(f"  task_success={task_success:.3f}  R_bad={R_bad_val:.3f}  R_bad_outcome={R_bad_out_val:.3f}  R_forge={R_forge_val:.3f}  Delta_auth={delta_auth_val:.3f}  exposure_rate={exp_rate:.3f}  n={len(logs)}")

    # By defense
    by_defense = defaultdict(list)
    for L in logs:
        by_defense[L.get("defense", "none")].append(L)

    metrics = []
    for defense, run_logs in by_defense.items():
        rate = aggregate_success_rate(run_logs)
        rb = r_bad(run_logs)
        rbo = r_bad_outcome(run_logs)
        rf = r_forge(run_logs)
        er = exposure_rate(run_logs)
        metrics.append({
            "defense": defense,
            "success_rate": rate,
            "R_bad": rb,
            "R_bad_outcome": rbo,
            "R_forge": rf,
            "exposure_rate": er,
            "n": len(run_logs),
        })

    out_path = os.path.join(metrics_dir, "by_defense.jsonl")
    write_jsonl(out_path, metrics)
    print(f"[ok] wrote by-defense metrics -> {out_path}")
    for m in metrics:
        print(f"  {m['defense']}: success={m['success_rate']:.3f} R_bad={m['R_bad']:.3f} R_bad_outcome={m['R_bad_outcome']:.3f} R_forge={m['R_forge']:.3f} exposure={m['exposure_rate']:.3f} n={m['n']}")

    # By defense × attack_strategy
    by_def_strat = defaultdict(list)
    for L in logs:
        key = (L.get("defense", "none"), L.get("attack_strategy", "all"))
        by_def_strat[key].append(L)

    strat_metrics = []
    for (defense, strategy), run_logs in sorted(by_def_strat.items()):
        rbo = r_bad_outcome(run_logs)
        strat_metrics.append({
            "defense": defense,
            "attack_strategy": strategy,
            "R_bad_outcome": rbo,
            "n": len(run_logs),
        })

    strat_path = os.path.join(metrics_dir, "by_defense_strategy.jsonl")
    write_jsonl(strat_path, strat_metrics)
    print(f"\n[ok] wrote defense×strategy metrics -> {strat_path}")
    print(f"{'Defense':<25} {'Strategy':<22} {'ASR':>8} {'n':>6}")
    print("-" * 65)
    for m in strat_metrics:
        print(f"  {m['defense']:<23} {m['attack_strategy']:<22} {m['R_bad_outcome']:>7.3f} {m['n']:>6}")


if __name__ == "__main__":
    main()
