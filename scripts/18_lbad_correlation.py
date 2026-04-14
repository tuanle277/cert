"""L_bad / ΔL_bad correlation analysis.

From the proposal:
    L_bad(o) = Σ_{τ ∈ T_bad} p_θ(τ | o)

We approximate this with the taint score (n-gram overlap with payload)
as a proxy for L_bad, and test whether ΔL_bad (change in taint score
between clean and attacked episodes) correlates with realized attack rates.

Outputs:
  - runs/lbad_correlation.json
  - runs/figures/lbad_correlation.png
  - runs/figures/lbad_delta_vs_asr.png
"""

import json
import os
import sys
from collections import defaultdict

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from cert_agent_exp.common.io import read_jsonl, ensure_dir
from cert_agent_exp.eval.metrics import is_bad_action, is_bad_outcome, r_forge

FIGURES_DIR = os.path.join("runs", "figures")
LOGS_PATH = os.path.join("runs", "logs", "grid_run.jsonl")


def compute_lbad_proxy(logs: list[dict]) -> list[dict]:
    """For each episode, compute L_bad proxy (taint score) and whether attack succeeded."""
    records = []
    for L in logs:
        vd = L.get("verifier_debug") or {}
        taint = vd.get("taint", {})
        taint_score = taint.get("ngram_score", 0.0)
        if taint_score == 0.0:
            dt = L.get("defense_trace", {})
            taint_score = dt.get("cert_taint_ratio", 0.0)

        exposure = L.get("exposure", {})
        has_injection = exposure.get("flag", False) if isinstance(exposure, dict) else bool(L.get("injected_sources"))
        bad_attempted = is_bad_action(L)
        bad_outcome = is_bad_outcome(L)

        records.append({
            "task_id": L.get("task_id", ""),
            "defense": L.get("defense", ""),
            "strategy": L.get("attack_strategy", ""),
            "taint_score": taint_score,
            "has_injection": has_injection,
            "bad_attempted": bad_attempted,
            "bad_outcome": bad_outcome,
        })
    return records


def compute_delta_lbad(records: list[dict]) -> dict:
    """Compute ΔL_bad: difference in mean taint score between attacked and clean outcomes."""
    by_defense = defaultdict(lambda: {"attacked_scores": [], "clean_scores": [],
                                       "bad_outcomes": 0, "total": 0})
    for r in records:
        d = by_defense[r["defense"]]
        d["total"] += 1
        if r["bad_outcome"]:
            d["attacked_scores"].append(r["taint_score"])
            d["bad_outcomes"] += 1
        else:
            d["clean_scores"].append(r["taint_score"])

    results = {}
    for defense, d in by_defense.items():
        mean_attacked = np.mean(d["attacked_scores"]) if d["attacked_scores"] else 0.0
        mean_clean = np.mean(d["clean_scores"]) if d["clean_scores"] else 0.0
        asr = d["bad_outcomes"] / max(1, d["total"])
        results[defense] = {
            "mean_taint_attacked": round(float(mean_attacked), 6),
            "mean_taint_clean": round(float(mean_clean), 6),
            "delta_lbad": round(float(mean_attacked - mean_clean), 6),
            "asr": round(asr, 4),
            "n": d["total"],
        }
    return results


def compute_r_forge_by_defense(logs: list[dict]) -> dict[str, float]:
    """R_forge (verifier FNR on bad actions) per defense, for cert / analysis."""
    by_def: dict[str, list[dict]] = defaultdict(list)
    for L in logs:
        by_def[L.get("defense", "")].append(L)
    out: dict[str, float] = {}
    for defense, subset in by_def.items():
        out[defense] = round(float(r_forge(subset)), 4)
    return out


def fig_lbad_distribution(records: list[dict]) -> None:
    """Histogram of taint scores for bad vs clean outcomes."""
    bad_scores = [r["taint_score"] for r in records if r["bad_outcome"]]
    clean_scores = [r["taint_score"] for r in records if not r["bad_outcome"]]

    fig, ax = plt.subplots(figsize=(9, 5))
    bins = np.linspace(0, max(0.15, max(bad_scores + clean_scores) * 1.1), 40)

    ax.hist(clean_scores, bins=bins, alpha=0.6, color="#4caf50", edgecolor="#2e7d32",
            label=f"Clean outcomes (n={len(clean_scores)})", linewidth=0.8)
    ax.hist(bad_scores, bins=bins, alpha=0.6, color="#e53935", edgecolor="#b71c1c",
            label=f"Bad outcomes (n={len(bad_scores)})", linewidth=0.8)

    ax.axvline(x=0.02, color="#333", linestyle="--", linewidth=1.5, alpha=0.7)
    ax.text(0.022, ax.get_ylim()[1] * 0.9, "τ = 0.02", fontsize=9, color="#555")

    ax.set_xlabel("Taint Score (L_bad proxy)", fontsize=12)
    ax.set_ylabel("Count", fontsize=12)
    ax.set_title("L_bad Distribution: Bad vs Clean Outcomes", fontsize=14, fontweight="bold")
    ax.legend(fontsize=10)
    ax.grid(True, alpha=0.3)

    out = os.path.join(FIGURES_DIR, "lbad_distribution.png")
    fig.tight_layout()
    fig.savefig(out, dpi=200)
    plt.close(fig)
    print(f"  [ok] {out}")


def fig_delta_vs_asr(delta_results: dict) -> None:
    """Scatter: ΔL_bad vs ASR by defense — tests whether cert gating flattens the landscape."""
    defenses = list(delta_results.keys())
    deltas = [delta_results[d]["delta_lbad"] for d in defenses]
    asrs = [delta_results[d]["asr"] for d in defenses]
    labels = [d.replace("_", " ")[:18] for d in defenses]

    fig, ax = plt.subplots(figsize=(9, 6))
    colors = ["#e53935" if a > 0.5 else "#ff9800" if a > 0.1 else "#4caf50" for a in asrs]

    ax.scatter(deltas, asrs, c=colors, s=150, edgecolors="black", linewidths=1.2, zorder=5)

    for i, label in enumerate(labels):
        ax.annotate(label, (deltas[i], asrs[i]),
                    textcoords="offset points", xytext=(8, 4), fontsize=8.5)

    corr = np.corrcoef(deltas, asrs)[0, 1] if len(deltas) > 1 else 0.0
    ax.text(0.02, 0.95, f"r = {corr:.3f}", transform=ax.transAxes,
            fontsize=11, fontweight="bold", color="#333",
            bbox=dict(boxstyle="round,pad=0.3", facecolor="#ffffcc", alpha=0.9))

    ax.set_xlabel("ΔL_bad (mean taint: attacked − clean)", fontsize=12)
    ax.set_ylabel("Attack Success Rate (ASR)", fontsize=12)
    ax.set_title("ΔL_bad vs ASR by Defense\n(Tests whether cert gating flattens the attacker's landscape)",
                 fontsize=13, fontweight="bold")
    ax.grid(True, alpha=0.3)
    ax.set_ylim(-0.05, 1.05)

    out = os.path.join(FIGURES_DIR, "lbad_delta_vs_asr.png")
    fig.tight_layout()
    fig.savefig(out, dpi=200)
    plt.close(fig)
    print(f"  [ok] {out}")


def main():
    ensure_dir(FIGURES_DIR)

    print("=" * 70)
    print("  L_bad / ΔL_bad CORRELATION ANALYSIS")
    print("=" * 70)

    if not os.path.exists(LOGS_PATH):
        print(f"  [error] {LOGS_PATH} not found. Run 05_run_grid.py first.")
        return

    logs = [json.loads(line) for line in open(LOGS_PATH)]
    print(f"  Loaded {len(logs)} episodes")

    records = compute_lbad_proxy(logs)
    delta_results = compute_delta_lbad(records)
    r_forge_by_def = compute_r_forge_by_defense(logs)
    for defense in delta_results:
        delta_results[defense]["R_forge"] = r_forge_by_def.get(defense, 0.0)

    print(f"\n  {'Defense':<28s} {'ΔL_bad':>8s} {'ASR':>8s} {'R_forge':>8s} {'n':>5s}")
    print("  " + "-" * 65)
    for defense in sorted(delta_results.keys()):
        d = delta_results[defense]
        print(
            f"  {defense:<28s} {d['delta_lbad']:>8.4f} {d['asr']:>8.3f} "
            f"{d.get('R_forge', 0.0):>8.3f} {d['n']:>5d}"
        )

    def _safe_corr(xs: list[float], ys: list[float]) -> float:
        if len(xs) < 2:
            return 0.0
        c = np.corrcoef(xs, ys)[0, 1]
        return float(c) if np.isfinite(c) else 0.0

    all_deltas = [delta_results[d]["delta_lbad"] for d in delta_results]
    all_asrs = [delta_results[d]["asr"] for d in delta_results]
    corr = _safe_corr(all_deltas, all_asrs)
    print(f"\n  Pearson r(ΔL_bad, ASR) = {corr:.4f}")

    rf_vals = [delta_results[d].get("R_forge", 0.0) for d in delta_results]
    corr_rf = _safe_corr(all_deltas, rf_vals)
    print(f"  Pearson r(ΔL_bad, R_forge) = {corr_rf:.4f}")

    output = {
        "description": "L_bad proxy analysis: taint score as surrogate for Σ p_θ(τ|o) over bad actions",
        "correlation": round(float(corr), 4),
        "correlation_delta_lbad_asr": round(float(corr), 4),
        "correlation_delta_lbad_r_forge": round(float(corr_rf), 4),
        "by_defense": delta_results,
        "n_episodes": len(records),
    }
    out_path = os.path.join("runs", "lbad_correlation.json")
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\n  [ok] {out_path}")

    print("\n  Generating figures...")
    fig_lbad_distribution(records)
    fig_delta_vs_asr(delta_results)


if __name__ == "__main__":
    main()
