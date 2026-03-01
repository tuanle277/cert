"""Plot frontiers, bar charts, and pipeline schematic."""

from pathlib import Path
from typing import Any


def _plt():
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    return plt


def plot_frontiers(
    metrics_by_config: dict[str, list[float]],
    x_label: str = "B_tokens",
    out_path: str = "runs/figures/frontier.png",
) -> None:
    try:
        plt = _plt()
    except ImportError:
        return
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    fig, ax = plt.subplots(figsize=(6, 4))
    for label, values in metrics_by_config.items():
        xs = list(range(len(values)))
        ax.plot(xs, values, marker="o", label=label, linewidth=2, markersize=8)
    ax.set_xlabel(x_label)
    ax.set_ylabel("Success rate")
    ax.legend()
    ax.set_ylim(-0.05, 1.05)
    fig.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close()


def plot_success_by_defense(
    defense_rates: dict[str, float],
    out_path: str = "runs/figures/success_by_defense.png",
) -> None:
    """Bar chart: success rate per defense (for slides/papers)."""
    try:
        plt = _plt()
    except ImportError:
        return
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    fig, ax = plt.subplots(figsize=(6, 4))
    names = list(defense_rates.keys())
    vals = [defense_rates[n] for n in names]
    colors = plt.cm.viridis([v for v in vals])
    bars = ax.bar(names, vals, color=colors, edgecolor="gray", linewidth=0.5)
    ax.set_ylabel("Success rate")
    ax.set_xlabel("Defense")
    ax.set_ylim(0, 1.05)
    for b, v in zip(bars, vals):
        ax.text(b.get_x() + b.get_width() / 2, b.get_height() + 0.02, f"{v:.2f}", ha="center", fontsize=9)
    plt.xticks(rotation=25, ha="right")
    fig.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close()


def plot_performance_by_defense(
    defense_stats: dict[str, dict],
    out_path: str = "runs/figures/performance_by_defense.png",
) -> None:
    """Bar chart: task success rate by defense with 95% bootstrap CI. defense_stats[def] = {rate, lower, upper, n}."""
    try:
        plt = _plt()
    except ImportError:
        return
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    fig, ax = plt.subplots(figsize=(7, 4))
    names = list(defense_stats.keys())
    rates = [defense_stats[d]["rate"] for d in names]
    err_lo = [defense_stats[d]["rate"] - defense_stats[d]["lower"] for d in names]
    err_hi = [defense_stats[d]["upper"] - defense_stats[d]["rate"] for d in names]
    n_vals = [defense_stats[d]["n"] for d in names]
    x = range(len(names))
    bars = ax.bar(x, rates, color="steelblue", edgecolor="black", linewidth=0.8)
    ax.errorbar(x, rates, yerr=[err_lo, err_hi], fmt="none", color="black", capsize=4, capthick=1.5)
    ax.set_xticks(x)
    ax.set_xticklabels(names, rotation=25, ha="right")
    ax.set_ylabel("Task success rate", fontsize=11)
    ax.set_xlabel("Defense", fontsize=11)
    ax.set_ylim(0, 1.08)
    ax.set_title("Performance: task success rate by defense (95% bootstrap CI)", fontsize=12)
    for i, (r, n) in enumerate(zip(rates, n_vals)):
        ax.text(i, r + 0.04, f"n={n}", ha="center", fontsize=9)
    fig.savefig(out_path, dpi=150, bbox_inches="tight", facecolor="white")
    plt.close()


def plot_exposure_and_injection(
    defense_stats: dict[str, dict],
    out_path: str = "runs/figures/exposure_and_injection.png",
) -> None:
    """Grouped bar: mean |exposed_sources| and mean |injected_sources| by defense (from run logs)."""
    try:
        plt = _plt()
    except ImportError:
        return
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    fig, ax = plt.subplots(figsize=(7, 4))
    names = list(defense_stats.keys())
    x = range(len(names))
    w = 0.35
    exposed = [defense_stats[d]["mean_exposed"] for d in names]
    injected = [defense_stats[d]["mean_injected"] for d in names]
    ax.bar([i - w / 2 for i in x], exposed, w, label="Exposed sources", color="steelblue", alpha=0.8)
    ax.bar([i + w / 2 for i in x], injected, w, label="Injected sources", color="coral", alpha=0.8)
    ax.set_xticks(x)
    ax.set_xticklabels(names, rotation=25, ha="right")
    ax.set_ylabel("Mean count per run", fontsize=11)
    ax.set_xlabel("Defense", fontsize=11)
    ax.legend()
    ax.set_title("Exposure: sources shown to model vs. sources that contained payload", fontsize=11)
    fig.savefig(out_path, dpi=150, bbox_inches="tight", facecolor="white")
    plt.close()


def plot_pipeline_schematic(out_path: str = "runs/figures/pipeline.png") -> None:
    """Pipeline overview: Download → Corpus → Tasks → Inject → Run → Metrics."""
    try:
        plt = _plt()
    except ImportError:
        return
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    fig, ax = plt.subplots(figsize=(10, 4))
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 4)
    ax.axis("off")
    steps = [
        (1.2, "Download\n(HotpotQA)", "data/raw/"),
        (2.8, "Corpus\n+ Index", "data/corpus/,\nindexes/"),
        (4.2, "Tasks", "data/tasks/"),
        (5.5, "Inject", "corpus_injected/"),
        (6.8, "Run grid", "runs/logs/"),
        (8.2, "Metrics\n& Plots", "runs/figures/"),
    ]
    for i, (x, label, sub) in enumerate(steps):
        box = plt.Rectangle((x - 0.45, 1.5), 0.9, 1.2, facecolor="steelblue", edgecolor="black", alpha=0.8)
        ax.add_patch(box)
        ax.text(x, 2.1, label, ha="center", va="center", fontsize=10, color="white", fontweight="bold")
        ax.text(x, 1.65, sub, ha="center", va="center", fontsize=7, color="white")
        if i < len(steps) - 1:
            ax.annotate("", xy=(x + 0.55, 2.1), xytext=(x + 0.45, 2.1),
                        arrowprops=dict(arrowstyle="->", color="black", lw=2))
    ax.set_title("cert-agent-exp pipeline", fontsize=14)
    fig.savefig(out_path, dpi=150, bbox_inches="tight", facecolor="white")
    plt.close()
