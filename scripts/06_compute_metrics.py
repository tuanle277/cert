"""Compute metrics from grid run logs: R_bad, R_forge, task success, exposure rate,
FRR, bootstrap CIs, and by-defense breakdown."""

import argparse
import json
import os
import yaml
from collections import defaultdict

from cert_agent_exp.common.io import ensure_dir, read_jsonl, write_jsonl
from cert_agent_exp.eval import (
    aggregate_success_rate, r_bad, r_bad_outcome, r_forge, delta_auth,
    exposure_rate, false_rejection_rate, clean_episode_count, bootstrap,
)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--n-bootstrap", type=int, default=1000)
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
    frr_val = false_rejection_rate(logs)
    n_clean = clean_episode_count(logs)

    # Bootstrap CIs for headline metrics
    _, asr_lo, asr_hi = bootstrap(logs, r_bad_outcome, n_bootstrap=args.n_bootstrap)

    baseline = {
        "task_success": task_success,
        "R_bad": R_bad_val,
        "R_bad_outcome": R_bad_out_val,
        "R_bad_outcome_CI95": [round(asr_lo, 4), round(asr_hi, 4)],
        "R_forge": R_forge_val,
        "Delta_auth": delta_auth_val,
        "exposure_rate": exp_rate,
        "false_rejection_rate": frr_val,
        "n_clean": n_clean,
        "n": len(logs),
    }
    baseline_path = os.path.join(metrics_dir, "baseline.json")
    with open(baseline_path, "w", encoding="utf-8") as f:
        json.dump(baseline, f, indent=2)
    print(f"[ok] baseline metrics -> {baseline_path}")
    print(f"  task_success={task_success:.3f}  R_bad={R_bad_val:.3f}  "
          f"R_bad_outcome={R_bad_out_val:.3f} [{asr_lo:.3f}, {asr_hi:.3f}]  "
          f"R_forge={R_forge_val:.3f}  Delta_auth={delta_auth_val:.3f}  "
          f"exposure={exp_rate:.3f}  FRR={frr_val:.3f} (n_clean={n_clean})  n={len(logs)}")

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
        frr = false_rejection_rate(run_logs)
        nc = clean_episode_count(run_logs)

        _, rbo_lo, rbo_hi = bootstrap(run_logs, r_bad_outcome, n_bootstrap=args.n_bootstrap)
        _, rate_lo, rate_hi = bootstrap(run_logs, aggregate_success_rate, n_bootstrap=args.n_bootstrap)

        metrics.append({
            "defense": defense,
            "success_rate": rate,
            "success_rate_CI95": [round(rate_lo, 4), round(rate_hi, 4)],
            "R_bad": rb,
            "R_bad_outcome": rbo,
            "R_bad_outcome_CI95": [round(rbo_lo, 4), round(rbo_hi, 4)],
            "R_forge": rf,
            "exposure_rate": er,
            "false_rejection_rate": frr,
            "n_clean": nc,
            "n": len(run_logs),
        })

    out_path = os.path.join(metrics_dir, "by_defense.jsonl")
    write_jsonl(out_path, metrics)
    print(f"[ok] wrote by-defense metrics -> {out_path}")
    for m in metrics:
        print(f"  {m['defense']}: success={m['success_rate']:.3f} R_bad={m['R_bad']:.3f} "
              f"ASR={m['R_bad_outcome']:.3f} [{m['R_bad_outcome_CI95'][0]:.3f},{m['R_bad_outcome_CI95'][1]:.3f}] "
              f"R_forge={m['R_forge']:.3f} FRR={m['false_rejection_rate']:.3f} "
              f"exposure={m['exposure_rate']:.3f} n={m['n']}")

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
