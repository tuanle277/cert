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
    """Bar chart: attack success rate (R_bad_outcome) by defense with 95% bootstrap CI."""
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
    colors = ["coral" if r > 0.5 else "steelblue" for r in rates]
    bars = ax.bar(x, rates, color=colors, edgecolor="black", linewidth=0.8, alpha=0.85)
    ax.errorbar(x, rates, yerr=[err_lo, err_hi], fmt="none", color="black", capsize=4, capthick=1.5)
    ax.set_xticks(x)
    ax.set_xticklabels(names, rotation=25, ha="right")
    ax.set_ylabel("Attack success rate (R_bad_outcome)", fontsize=11)
    ax.set_xlabel("Defense", fontsize=11)
    ax.set_ylim(0, 1.08)
    ax.set_title("Attack success rate by defense (95% bootstrap CI)\nlower is better", fontsize=12)
    for i, (r, n) in enumerate(zip(rates, n_vals)):
        ax.text(i, r + 0.04, f"{r:.2f}\nn={n}", ha="center", fontsize=9)
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


def plot_security_by_defense(
    defense_metrics: dict[str, dict],
    out_path: str = "runs/figures/security_by_defense.png",
) -> None:
    """Grouped bar: R_bad (attempted) vs R_bad_outcome (executed) by defense.

    defense_metrics[def] = {"R_bad": float, "R_bad_outcome": float, "n": int}
    """
    try:
        plt = _plt()
    except ImportError:
        return
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    fig, ax = plt.subplots(figsize=(8, 4.5))
    names = list(defense_metrics.keys())
    x = list(range(len(names)))
    w = 0.35
    r_bad_vals = [defense_metrics[d]["R_bad"] for d in names]
    r_outcome_vals = [defense_metrics[d]["R_bad_outcome"] for d in names]
    bars1 = ax.bar([i - w / 2 for i in x], r_bad_vals, w, label="R_bad (attempted)", color="coral", alpha=0.85, edgecolor="black", linewidth=0.6)
    bars2 = ax.bar([i + w / 2 for i in x], r_outcome_vals, w, label="R_bad_outcome (executed)", color="steelblue", alpha=0.85, edgecolor="black", linewidth=0.6)
    ax.set_xticks(x)
    ax.set_xticklabels(names, rotation=25, ha="right")
    ax.set_ylabel("Rate", fontsize=11)
    ax.set_xlabel("Defense", fontsize=11)
    ax.set_ylim(0, 1.12)
    ax.legend(loc="upper right")
    ax.set_title("Security: bad-action rates by defense (attempted vs. executed)", fontsize=12)
    for i, (rb, ro) in enumerate(zip(r_bad_vals, r_outcome_vals)):
        ax.text(i - w / 2, rb + 0.02, f"{rb:.2f}", ha="center", fontsize=8)
        ax.text(i + w / 2, ro + 0.02, f"{ro:.2f}", ha="center", fontsize=8)
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
        from matplotlib.patches import Rectangle
        box = Rectangle((x - 0.45, 1.5), 0.9, 1.2, facecolor="steelblue", edgecolor="black", alpha=0.8)
        ax.add_patch(box)
        ax.text(x, 2.1, label, ha="center", va="center", fontsize=10, color="white", fontweight="bold")
        ax.text(x, 1.65, sub, ha="center", va="center", fontsize=7, color="white")
        if i < len(steps) - 1:
            ax.annotate("", xy=(x + 0.55, 2.1), xytext=(x + 0.45, 2.1),
                        arrowprops=dict(arrowstyle="->", color="black", lw=2))
    ax.set_title("cert-agent-exp pipeline", fontsize=14)
    fig.savefig(out_path, dpi=150, bbox_inches="tight", facecolor="white")
    plt.close()


def plot_defense_vs_strategy_heatmap(
    strat_metrics: list[dict[str, Any]],
    out_path: str,
) -> None:
    """Heatmap: defense (rows) × attack_strategy (columns), value = ASR (R_bad_outcome)."""
    plt = _plt()
    import numpy as np

    defenses_order = [
        "none", "quote_only", "provenance_tags", "allowlist",
        "quote+prov+allowlist", "certificate_gating",
        "taskshield", "llm_judge", "intentguard",
    ]
    strategies_order = list(dict.fromkeys(
        m["attack_strategy"] for m in strat_metrics if m.get("attack_strategy")
    ))

    defenses = [d for d in defenses_order if d in {m["defense"] for m in strat_metrics}]
    for d in {m["defense"] for m in strat_metrics}:
        if d not in defenses:
            defenses.append(d)

    lookup = {}
    for m in strat_metrics:
        lookup[(m["defense"], m["attack_strategy"])] = m.get("R_bad_outcome", 0.0)

    data = np.zeros((len(defenses), len(strategies_order)))
    for i, d in enumerate(defenses):
        for j, s in enumerate(strategies_order):
            data[i, j] = lookup.get((d, s), 0.0)

    fig, ax = plt.subplots(figsize=(max(8, len(strategies_order) * 1.3), max(5, len(defenses) * 0.6)))
    cmap = plt.cm.RdYlGn_r
    im = ax.imshow(data, cmap=cmap, aspect="auto", vmin=0, vmax=1)
    fig.colorbar(im, ax=ax, label="Attack Success Rate (ASR)")

    ax.set_xticks(range(len(strategies_order)))
    ax.set_xticklabels(strategies_order, rotation=40, ha="right", fontsize=9)
    ax.set_yticks(range(len(defenses)))
    ax.set_yticklabels(defenses, fontsize=9)

    for i in range(len(defenses)):
        for j in range(len(strategies_order)):
            val = data[i, j]
            color = "white" if val > 0.5 else "black"
            ax.text(j, i, f"{val:.2f}", ha="center", va="center", fontsize=8, color=color)

    ax.set_title("Attack Success Rate: Defense × Attack Strategy", fontsize=12, pad=12)
    ax.set_xlabel("Attack Strategy")
    ax.set_ylabel("Defense")
    fig.savefig(out_path, dpi=150, bbox_inches="tight", facecolor="white")
    plt.close()
