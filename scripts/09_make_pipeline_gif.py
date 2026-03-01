"""Export pipeline steps as PNG frames; then combine to GIF with: imageio or ffmpeg."""

import os
import yaml


def main() -> None:
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib required")
        return

    cfg = yaml.safe_load(open("configs/grid.yaml", "r"))
    figures_dir = os.path.join(cfg.get("runs_dir", "runs"), "figures", "gif_frames")
    os.makedirs(figures_dir, exist_ok=True)

    steps = [
        ("Download", "data/raw/", "HotpotQA"),
        ("Corpus + Index", "data/corpus/, indexes/", "Chunk, embed, FAISS"),
        ("Tasks", "data/tasks/", "Goals, context_titles"),
        ("Inject", "corpus_injected/", "Payloads + manifest"),
        ("Run grid", "runs/logs/", "exposed_sources, metrics"),
    ]
    for i, (label, sub, detail) in enumerate(steps):
        fig, ax = plt.subplots(figsize=(6, 3))
        ax.set_xlim(0, 6)
        ax.set_ylim(0, 3)
        ax.axis("off")
        for j, (l, s, d) in enumerate(steps):
            highlight = j == i
            color = "steelblue" if highlight else "lightgray"
            alpha = 1.0 if highlight else 0.5
            box = plt.Rectangle((0.5 + j * 1.1, 1), 1, 1.2, facecolor=color, edgecolor="black", alpha=alpha)
            ax.add_patch(box)
            ax.text(1.0 + j * 1.1, 1.6, l, ha="center", va="center", fontsize=9, fontweight="bold" if highlight else "normal")
            ax.text(1.0 + j * 1.1, 1.2, s, ha="center", va="center", fontsize=7)
        ax.set_title(f"cert-agent-exp pipeline — step {i+1}/{len(steps)}: {label}", fontsize=11)
        path = os.path.join(figures_dir, f"frame_{i:02d}.png")
        fig.savefig(path, dpi=120, bbox_inches="tight", facecolor="white")
        plt.close()
        print(f"[ok] {path}")

    out_gif = os.path.join(os.path.dirname(figures_dir), "pipeline.gif")
    try:
        import imageio.v3 as iio
        paths = [os.path.join(figures_dir, f"frame_{i:02d}.png") for i in range(len(steps))]
        frames = [iio.imread(p) for p in paths]
        # Hold each frame ~1 sec at 2 fps
        iio.imwrite(out_gif, frames + frames, duration=0.5, loop=0)
        print(f"[ok] GIF -> {out_gif}")
    except ImportError:
        print("Optional: pip install imageio then re-run to build pipeline.gif")
        print(f"Or: ffmpeg -framerate 1 -i {figures_dir}/frame_%02d.png -vf 'setpts=2*PTS' {out_gif}")


if __name__ == "__main__":
    main()
