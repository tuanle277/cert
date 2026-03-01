"""Generate all show figures: pipeline schematic, attack flow, optional GIF frames."""

import argparse
import os
import yaml

from cert_agent_exp.eval import plot_pipeline_schematic


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="configs/grid.yaml", help="Config for runs_dir")
    ap.add_argument("--out-dir", default=None, help="Figures dir (default: runs/figures)")
    args = ap.parse_args()

    if args.out_dir:
        figures_dir = args.out_dir
    else:
        cfg = yaml.safe_load(open(args.config, "r"))
        runs_dir = cfg.get("runs_dir", "runs")
        figures_dir = os.path.join(runs_dir, "figures")
    os.makedirs(figures_dir, exist_ok=True)

    # 1. Pipeline overview (for README / slides)
    pipeline_path = os.path.join(figures_dir, "pipeline.png")
    plot_pipeline_schematic(out_path=pipeline_path)
    print(f"[ok] pipeline -> {pipeline_path}")

    # 2. Attack channel / injection flow (schematic)
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        fig, ax = plt.subplots(figsize=(7, 4))
        ax.set_xlim(0, 7)
        ax.set_ylim(0, 4)
        ax.axis("off")
        ax.add_patch(plt.Rectangle((0.5, 1.5), 1.2, 1, facecolor="lightcoral", edgecolor="black"))
        ax.text(1.1, 2, "Attacker\npayload", ha="center", va="center", fontsize=9)
        ax.annotate("", xy=(2.2, 2), xytext=(1.7, 2), arrowprops=dict(arrowstyle="->", lw=2))
        ax.add_patch(plt.Rectangle((2.2, 1.5), 1.4, 1, facecolor="wheat", edgecolor="black"))
        ax.text(2.9, 2, "Inject into\ncorpus chunk", ha="center", va="center", fontsize=9)
        ax.annotate("", xy=(4.1, 2), xytext=(3.6, 2), arrowprops=dict(arrowstyle="->", lw=2))
        ax.add_patch(plt.Rectangle((4.1, 1.5), 1.4, 1, facecolor="lightblue", edgecolor="black"))
        ax.text(4.8, 2, "Retrieval\n→ Agent", ha="center", va="center", fontsize=9)
        ax.annotate("", xy=(5.9, 2), xytext=(5.5, 2), arrowprops=dict(arrowstyle="->", lw=2))
        ax.add_patch(plt.Rectangle((5.9, 1.5), 1, 1, facecolor="lightgreen", edgecolor="black"))
        ax.text(6.4, 2, "Verifier\n/ Log", ha="center", va="center", fontsize=9)
        ax.set_title("Attack channel: injection → retrieval → agent → verifier", fontsize=11)
        attack_path = os.path.join(figures_dir, "attack_flow.png")
        fig.savefig(attack_path, dpi=150, bbox_inches="tight", facecolor="white")
        plt.close()
        print(f"[ok] attack flow -> {attack_path}")
    except Exception as e:
        print(f"[skip] attack_flow: {e}")

    # 3. Exposure vs injected (concept diagram)
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        fig, ax = plt.subplots(figsize=(5, 4))
        ax.bar(["Exposed\nsources"], [1.0], color="steelblue", alpha=0.7, label="Shown to model")
        ax.bar(["Injected\nsources"], [0.3], color="coral", alpha=0.7, label="Contained payload")
        ax.set_ylabel("Fraction of runs")
        ax.set_ylim(0, 1.1)
        ax.legend()
        ax.set_title("Logging: exposed_sources vs injected_sources")
        exposure_path = os.path.join(figures_dir, "exposure_concept.png")
        fig.savefig(exposure_path, dpi=150, bbox_inches="tight", facecolor="white")
        plt.close()
        print(f"[ok] exposure concept -> {exposure_path}")
    except Exception as e:
        print(f"[skip] exposure_concept: {e}")

    print(f"\nFigures in {figures_dir}: pipeline.png, attack_flow.png, exposure_concept.png")
    print("(Also run 07_plot_frontiers.py for frontier.png, success_by_defense.png)")


if __name__ == "__main__":
    main()
