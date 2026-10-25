"""Training-curve plots for every GRPO run, plus a held-out check for overfitting.

    python scripts/plot_training.py            # -> results/training_plots/*.png

GRPO has no supervised "training error": its loss is a policy-gradient
surrogate that hovers near zero by construction. The useful curves are the
training *reward* and *solve rate* (shown as error = 1 - solve rate), the KL
from the base model and the policy entropy. Overfitting shows up as held-out
pass@1 falling while the training solve rate keeps rising, so the last plot
puts both on one axis for the run whose checkpoints were all evaluated.
"""

from __future__ import annotations

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "results" / "training_plots"

# Fixed categorical order (one hue per run, never re-assigned).
RUNS = [
    ("qwen05b", "0.5B (grader v1)", "runs/qwen05b/checkpoint-150/trainer_state.json", "#2a78d6"),
    ("coder15", "1.5B first run (grader v1)", "runs/coder15/checkpoint-100/trainer_state.json", "#eb6834"),
    ("final", "1.5B final (grader v2)", "runs/final_coder15/log_history.json", "#1baf7a"),
    ("hardened", "1.5B hardened (grader v3)", "runs/hardened_coder15/log_history.json", "#eda100"),
]
INK, MUTED, GRID = "#0b0b0b", "#52514e", "#e4e3df"


def load(path: str) -> list[dict]:
    data = json.loads((ROOT / path).read_text(encoding="utf-8"))
    hist = data["log_history"] if isinstance(data, dict) else data
    return [h for h in hist if "reward" in h]


def smooth(ys, w=10):
    out = []
    for i in range(len(ys)):
        win = ys[max(0, i - w + 1): i + 1]
        out.append(sum(win) / len(win))
    return out


def style(ax, title, ylabel, xlabel="training step"):
    ax.set_title(title, loc="left", fontsize=13, color=INK, pad=12)
    ax.set_xlabel(xlabel, color=MUTED)
    ax.set_ylabel(ylabel, color=MUTED)
    ax.grid(True, color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    for s in ("left", "bottom"):
        ax.spines[s].set_color(GRID)
    ax.tick_params(colors=MUTED)


def line_plot(fname, key, title, ylabel, transform=lambda v: v, note="", ylim=None):
    fig, ax = plt.subplots(figsize=(9, 5), dpi=130)
    ends = []  # (x, y) of end labels already placed, to keep them from overlapping
    for _, label, path, color in RUNS:
        hist = [h for h in load(path) if key in h]
        if not hist:
            continue
        xs = [h["step"] for h in hist]
        ys = [transform(h[key]) for h in hist]
        ax.plot(xs, ys, color=color, linewidth=1, alpha=0.25)
        sm = smooth(ys)
        ax.plot(xs, sm, color=color, linewidth=2, label=label)
        dy = -11 if any(x == xs[-1] and abs(y - sm[-1]) < 0.03 for x, y in ends) else 0
        ends.append((xs[-1], sm[-1]))
        ax.annotate(f"{sm[-1]:.2f}", (xs[-1], sm[-1]), xytext=(6, dy),
                    textcoords="offset points", va="center", fontsize=9, color=INK)
    style(ax, title, ylabel)
    if ylim:
        ax.set_ylim(*ylim)
    ax.legend(frameon=False, fontsize=9, labelcolor=INK)
    if note:
        fig.text(0.01, 0.01, note, fontsize=8, color=MUTED)
    fig.tight_layout(rect=(0, 0.04 if note else 0, 1, 1))
    fig.savefig(OUT / fname)
    plt.close(fig)


def heldout_vs_train():
    """Overfitting check: training solve rate vs held-out pass@1 per checkpoint."""
    pts = []
    for step, path in [(0, "eval_hardened_base_proc.json"), (400, "eval_hardened_trained_proc.json")] + \
            [(s, f"eval_ckpt_hardened_{s}_proc.json") for s in range(50, 400, 50)]:
        p = ROOT / "results" / path
        if p.exists():
            d = json.loads(p.read_text(encoding="utf-8"))
            pts.append((step, d.get("summary", d)["pass_at_1"]))
    pts.sort()
    hist = [h for h in load(RUNS[3][2]) if "env/solved" in h]
    xs = [h["step"] for h in hist]
    fig, ax = plt.subplots(figsize=(9, 5), dpi=130)
    ax.plot(xs, smooth([h["env/solved"] for h in hist]), color="#eda100", linewidth=2,
            label="training batches: solve rate (smoothed)")
    ax.plot([p[0] for p in pts], [p[1] for p in pts], color="#2a78d6", linewidth=2,
            marker="o", markersize=8, markeredgecolor="white", markeredgewidth=2,
            label="held-out generated tasks: pass@1 (200 tasks, k=4)")
    for x, y in pts:
        ax.annotate(f"{y:.0%}", (x, y), xytext=(0, -16), textcoords="offset points",
                    ha="center", fontsize=9, color=INK)
    style(ax, "Hardened run: training vs held-out (overfitting check)", "rate")
    ax.set_ylim(0, 1.05)
    ax.legend(frameon=False, fontsize=9, labelcolor=INK, loc="lower right")
    fig.text(0.01, 0.01, "Overfitting would show as the blue held-out line falling while the "
             "training line keeps rising.", fontsize=8, color=MUTED)
    fig.tight_layout(rect=(0, 0.04, 1, 1))
    fig.savefig(OUT / "5_heldout_vs_train_hardened.png")
    plt.close(fig)
    return pts


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    grader_note = ("Rewards are not comparable across grader versions: v1 paid for "
                   "some insecure fixes; v2/v3 gate security credit on working code.")
    line_plot("1_train_reward.png", "reward", "Training reward per step (higher is better)",
              "mean reward", note=grader_note, ylim=(0, 1))
    line_plot("2_train_error.png", "env/solved", "Training error = 1 - solve rate (lower is better)",
              "error", transform=lambda v: 1 - v, note="0.5B run did not log solve rate.",
              ylim=(0, 1))
    line_plot("3_kl.png", "kl", "KL divergence from the base model",
              "KL", note="How far the policy has moved from the starting model.")
    line_plot("4_entropy.png", "entropy", "Policy entropy (answer diversity)", "entropy",
              note="A collapse towards 0 means the model always gives the same answer.")
    pts = heldout_vs_train()
    for _, label, path, _ in RUNS:
        hist = load(path)
        last = hist[-1]
        print(f"{label:28s} steps={last['step']:4d} epoch={last.get('epoch', 0):.2f} "
              f"reward {sum(h['reward'] for h in hist[:10]) / 10:.2f} -> "
              f"{sum(h['reward'] for h in hist[-10:]) / 10:.2f}")
    print("held-out:", [(s, round(v, 3)) for s, v in pts])
    print("wrote", OUT)


if __name__ == "__main__":
    main()
