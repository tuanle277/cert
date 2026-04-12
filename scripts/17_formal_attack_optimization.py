"""Formal attack optimization aligned with the proposal objective.

Implements:  max_{δ ∈ C}  E[ 1{a ∈ B} - λ · ℓ_task ]
subject to:  |δ| ≤ B,  K sources,  plausibility(δ) ≥ τ_plaus

Outputs:
  - runs/formal_attack_optimization.json  (structured results)
  - runs/figures/formal_attack_objective.png
  - runs/figures/plausibility_vs_evasion.png
"""

import argparse
import json
import os
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from cert_agent_exp.attacks.optimizer import (
    optimize_attack,
    PAYLOAD_VARIANTS,
    STRATEGIES,
    BUDGETS,
    PLACEMENTS,
)
from cert_agent_exp.common.io import ensure_dir

FIGURES_DIR = os.path.join("runs", "figures")


def fig_objective_by_strategy(results: dict) -> None:
    strats = results["by_strategy"]
    names = list(strats.keys())
    means = [strats[n]["mean"] for n in names]
    maxes = [strats[n]["max"] for n in names]
    labels = [n.replace("_", " ").title() for n in names]

    fig, ax = plt.subplots(figsize=(10, 5.5))
    y = np.arange(len(names))

    ax.barh(y, maxes, height=0.5, color="#ef9a9a", edgecolor="#c62828",
            linewidth=0.8, label="Best config", alpha=0.7)
    ax.barh(y, means, height=0.5, color="#e53935", edgecolor="#b71c1c",
            linewidth=1.2, label="Mean across configs")

    for i in range(len(names)):
        ax.text(maxes[i] + 0.015, y[i], f"{maxes[i]:.3f}", va="center",
                fontsize=9, color="#333")

    ax.set_yticks(y)
    ax.set_yticklabels(labels, fontsize=10)
    ax.invert_yaxis()
    ax.set_xlabel(r"Objective  $\mathbb{E}[\mathbf{1}\{a \in \mathcal{B}\}] - \lambda \cdot \ell_{\mathrm{task}}$",
                  fontsize=11)
    ax.set_title("Formal Attack Objective by Strategy", fontsize=14, fontweight="bold")
    ax.legend(loc="lower right", fontsize=10)
    ax.set_xlim(-0.1, 1.0)
    ax.grid(True, axis="x", alpha=0.3)

    out = os.path.join(FIGURES_DIR, "formal_attack_objective.png")
    fig.tight_layout()
    fig.savefig(out, dpi=200)
    plt.close(fig)
    print(f"  [ok] {out}")


def fig_plausibility_vs_evasion(results: dict) -> None:
    top = results["top_10"]
    if not top:
        print("  [skip] no candidates for plausibility plot")
        return

    plaus = [c["plausibility"] for c in top]
    evasion = [c["evasion_rate"] for c in top]
    obj = [c["objective"] for c in top]
    labels = [c["strategy"].replace("_", " ")[:15] for c in top]

    fig, ax = plt.subplots(figsize=(8, 6))
    scatter = ax.scatter(plaus, evasion, c=obj, cmap="RdYlGn", s=120,
                         edgecolors="black", linewidths=1, vmin=-0.5, vmax=1.0)
    plt.colorbar(scatter, ax=ax, label="Objective score")

    for i, label in enumerate(labels):
        ax.annotate(label, (plaus[i], evasion[i]),
                    textcoords="offset points", xytext=(6, 4), fontsize=7.5)

    ax.set_xlabel("Plausibility Score", fontsize=12)
    ax.set_ylabel("Evasion Rate", fontsize=12)
    ax.set_title("Plausibility vs Evasion (Top 10 Attacks)", fontsize=14, fontweight="bold")
    ax.set_xlim(0, 1.05)
    ax.set_ylim(-0.05, 1.05)
    ax.grid(True, alpha=0.3)

    out = os.path.join(FIGURES_DIR, "plausibility_vs_evasion.png")
    fig.tight_layout()
    fig.savefig(out, dpi=200)
    plt.close(fig)
    print(f"  [ok] {out}")


def fig_budget_sweep(results: dict) -> None:
    by_budget = results["by_budget"]
    budgets = sorted(by_budget.keys(), key=int)
    means = [by_budget[b]["mean"] for b in budgets]
    maxes = [by_budget[b]["max"] for b in budgets]

    fig, ax = plt.subplots(figsize=(8, 5))
    x = [int(b) for b in budgets]
    ax.plot(x, maxes, "o-", color="#e53935", linewidth=2.5, markersize=8,
            label="Best attack", markeredgecolor="#b71c1c")
    ax.plot(x, means, "s--", color="#1976d2", linewidth=2, markersize=7,
            label="Mean attack", markeredgecolor="#0d47a1")
    ax.fill_between(x, means, maxes, alpha=0.1, color="#e53935")

    ax.set_xlabel("Token Budget B", fontsize=12)
    ax.set_ylabel("Objective Score", fontsize=12)
    ax.set_title("Attack Objective vs Token Budget", fontsize=14, fontweight="bold")
    ax.legend(fontsize=10)
    ax.grid(True, alpha=0.3)
    ax.set_ylim(-0.1, 1.0)

    out = os.path.join(FIGURES_DIR, "attack_budget_sweep.png")
    fig.tight_layout()
    fig.savefig(out, dpi=200)
    plt.close(fig)
    print(f"  [ok] {out}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--payload-dir", default="assets/attack_payloads")
    ap.add_argument("--lambda", type=float, default=0.3, dest="lam")
    ap.add_argument("--threshold", type=float, default=0.02)
    ap.add_argument("--plausibility", type=float, default=0.3)
    ap.add_argument("--output", default="runs/formal_attack_optimization.json")
    args = ap.parse_args()

    ensure_dir(FIGURES_DIR)
    ensure_dir(os.path.dirname(args.output))

    print("=" * 70)
    print("  FORMAL ATTACK OPTIMIZATION (Proposal-Aligned)")
    print(f"  Objective: max_δ E[1{{a∈B}}] - {args.lam}·ℓ_task")
    print(f"  Constraints: |δ|≤B, plausibility≥{args.plausibility}, τ={args.threshold}")
    print("=" * 70)

    results = optimize_attack(
        payload_dir=args.payload_dir,
        lam=args.lam,
        ngram_threshold=args.threshold,
        plausibility_threshold=args.plausibility,
    )

    with open(args.output, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n  [ok] Results -> {args.output}")

    best = results["best_attack"]
    if best:
        print(f"\n  Best attack (obj={best['objective']:.4f}):")
        print(f"    Payload:      {best['payload']}")
        print(f"    Strategy:     {best['strategy']} ({best['template']})")
        print(f"    Budget:       {best['budget']} tokens")
        print(f"    Placement:    {best['placement']}")
        print(f"    Plausibility: {best['plausibility']:.3f}")
        print(f"    Evasion:      {best['evasion_rate']*100:.1f}%")
        print(f"    Est. ASR:     {best['estimated_asr']*100:.1f}%")
        print(f"    Task loss:    {best['task_loss']:.1f}")

    ss = results["search_space"]
    print(f"\n  Search space: {ss['total_candidates']} total, "
          f"{ss['plausibility_filtered']} filtered by plausibility, "
          f"{ss['evaluated']} evaluated")

    print("\n  Generating figures...")
    fig_objective_by_strategy(results)
    fig_plausibility_vs_evasion(results)
    fig_budget_sweep(results)


if __name__ == "__main__":
    main()
