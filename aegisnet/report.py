"""Figures (matplotlib) and a single-file HTML report."""
import base64
import html
import textwrap
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from .data import FEATURES
from .explain import PRETTY

BG, PANEL, FG, MUTED = "#0A0F1F", "#121B33", "#E8EEFF", "#7F8DB3"
AQUA, RED, AMBER, VIOLET = "#00F0C8", "#FF3D71", "#FFB020", "#8B7BFF"


def _style():
    plt.rcParams.update({"figure.facecolor": BG, "axes.facecolor": PANEL, "axes.edgecolor": MUTED,
                         "axes.labelcolor": FG, "xtick.color": MUTED, "ytick.color": MUTED, "text.color": FG,
                         "axes.grid": True, "grid.color": "#22305A", "grid.alpha": 0.6, "font.size": 11,
                         "axes.spines.top": False, "axes.spines.right": False, "legend.facecolor": PANEL,
                         "legend.edgecolor": MUTED, "savefig.facecolor": BG})


def fig_training(model, path):
    _style()
    f, ax = plt.subplots(1, 2, figsize=(10, 3.8))
    ax[0].plot(model.hist_ae["train"], color=AQUA, lw=2, label="train")
    ax[0].plot(model.hist_ae["val"], color=AMBER, lw=2, ls="--", label="validation")
    ax[0].set(title="Brain 1 - Autoencoder (MSE)", xlabel="epoch"); ax[0].legend()
    ax[1].semilogy(model.hist_clf["train"], color=AQUA, lw=2, label="train")
    ax[1].semilogy(model.hist_clf["val"], color=AMBER, lw=2, ls="--", label="validation")
    ax[1].set(title="Brain 2 - Classifier (cross-entropy)", xlabel="epoch"); ax[1].legend()
    f.tight_layout(); f.savefig(path, dpi=160); plt.close(f)


def fig_roc(curves, path):
    _style()
    f, ax = plt.subplots(figsize=(6, 4.6))
    cols = [AQUA, VIOLET, AMBER, RED]
    for (name, (fpr, tpr, auc)), c in zip(curves.items(), cols):
        ax.plot(fpr, tpr, color=c, lw=2.2, label=f"{name} (AUC {auc:.3f})")
    ax.plot([0, 1], [0, 1], color=MUTED, ls=":")
    ax.set(xlabel="False positive rate", ylabel="True positive rate", title="Detection quality (ROC)")
    ax.legend(loc="lower right"); f.tight_layout(); f.savefig(path, dpi=160); plt.close(f)


def fig_confusion(cm, rows, cols, path):
    _style()
    f, ax = plt.subplots(figsize=(8, 5.2))
    norm = cm / np.maximum(cm.sum(1, keepdims=True), 1)
    ax.imshow(norm, cmap="viridis", vmin=0, vmax=1); ax.grid(False)
    ax.set_xticks(range(len(cols))); ax.set_xticklabels(cols, rotation=35, ha="right")
    ax.set_yticks(range(len(rows))); ax.set_yticklabels(rows)
    for i in range(len(rows)):
        for j in range(len(cols)):
            if cm[i, j]:
                ax.text(j, i, f"{norm[i, j]*100:.0f}%", ha="center", va="center",
                        color="white" if norm[i, j] < 0.6 else "black", fontsize=9)
    ax.set(xlabel="AegisNet decision", ylabel="Ground truth", title="What AegisNet decided for every minute")
    f.tight_layout(); f.savefig(path, dpi=160); plt.close(f)


def fig_timeline(test, pred, path):
    _style()
    y = (test["label"] != "normal").to_numpy()
    lab = test["label"].to_numpy()
    day = int(np.argmax([len(set(lab[d * 1440:(d + 1) * 1440])) for d in range(len(test) // 1440)]))  # day with most attack types
    s, e = day * 1440, (day + 1) * 1440
    t = np.arange(e - s) / 60.0
    f, ax = plt.subplots(figsize=(11, 3.8))
    ax.fill_between(t, 0, 100, where=y[s:e], color=RED, alpha=0.25, label="real attack (ground truth)")
    ax.plot(t, pred["risk"].to_numpy()[s:e], color=AQUA, lw=1.4, label="AegisNet risk score")
    ax.axhline(50, color=AMBER, ls="--", lw=1, label="alert level")
    a = pred["alert"].to_numpy()[s:e]
    ax.scatter(t[a], np.full(a.sum(), 104), color=AMBER, s=8, label="alert raised", clip_on=False)
    ax.set(xlabel="hour of day", ylabel="risk (0-100)", xlim=(0, 24), ylim=(0, 100))
    ax.legend(loc="upper center", ncol=4, fontsize=8.5, bbox_to_anchor=(0.5, -0.22))
    f.tight_layout(); f.savefig(path, dpi=160); plt.close(f)


def fig_explain(incs, path):
    """incs: list of (title, incident dict) -> 'why did the AI alert?' bar charts."""
    _style()
    f, axs = plt.subplots(1, len(incs), figsize=(5.6 * len(incs), 3.8))
    axs = np.atleast_1d(axs)
    for ax, (title, inc) in zip(axs, incs):
        w = inc["why"][::-1]
        names = [x["name"] for x in w]
        ax.barh(names, [x["share"] * 100 for x in w], color=AQUA)
        for i, x in enumerate(w):
            ax.text(x["share"] * 100 + 1, i, f'{x["observed"]:.0f} vs expected ~{x["expected"]:.0f}', va="center", fontsize=9, color=FG)
        ax.set(title=title, xlabel="share of anomaly explained (%)", xlim=(0, 115)); ax.grid(False)
    f.tight_layout(); f.savefig(path, dpi=160); plt.close(f)


def fig_zeroday(rates, path):
    _style()
    f, ax = plt.subplots(figsize=(7, 4.2))
    names = list(rates)
    vals = [rates[n] * 100 for n in names]
    bars = ax.bar([textwrap.fill(n, 13) for n in names], vals, color=[MUTED, VIOLET, AQUA, AMBER, RED][:len(names)])
    for b, v in zip(bars, vals):
        ax.text(b.get_x() + b.get_width() / 2, v + 1.5, f"{v:.0f}%", ha="center", fontweight="bold")
    ax.set(ylim=(0, 115), ylabel="% of unseen-attack minutes", title="Zero-day test: ransomware never shown in training")
    plt.setp(ax.get_xticklabels(), fontsize=9); ax.grid(axis="x", visible=False)
    f.tight_layout(); f.savefig(path, dpi=160); plt.close(f)


def fig_drift(stable, drifted, path):
    _style()
    f, ax = plt.subplots(figsize=(6.4, 3.9))
    x = np.arange(len(FEATURES)); w = 0.4
    ax.bar(x - w / 2, [stable["psi"][k] for k in FEATURES], w, color=AQUA, label="normal week")
    ax.bar(x + w / 2, [drifted["psi"][k] for k in FEATURES], w, color=RED, label="after traffic change")
    ax.axhline(0.25, color=AMBER, ls="--", label="drift alarm (PSI 0.25)")
    ax.set_xticks(x); ax.set_xticklabels([PRETTY[k] for k in FEATURES], rotation=50, ha="right", fontsize=9)
    top = max(max(stable["psi"].values()), max(drifted["psi"].values()))
    ax.set(ylabel="PSI (log scale)", title="Drift Watchdog"); ax.legend(loc="upper right", fontsize=9); ax.set_yscale("symlog", linthresh=0.1)
    ax.set_ylim(0, top * 3)
    f.tight_layout(); f.savefig(path, dpi=160); plt.close(f)


def _b64(p):
    return base64.b64encode(open(p, "rb").read()).decode()


def build_html(res, figdir, samples, path):
    cards = "".join(f'<div class="c"><b>{html.escape(str(v))}</b><span>{html.escape(k)}</span></div>' for k, v in res["headline"].items())
    figs = [("training.png", "Training curves"), ("roc.png", "ROC curves"), ("timeline.png", "Live-monitoring timeline"),
            ("confusion.png", "Decision matrix"), ("explain.png", "Explainable alerts"),
            ("zeroday.png", "Zero-day experiment"), ("drift.png", "Drift watchdog")]
    imgs = "".join(f'<h2>{t}</h2><img src="data:image/png;base64,{_b64(f"{figdir}/{n}")}">' for n, t in figs)
    inc = "".join(f"<pre>{html.escape(s)}</pre>" for s in samples)
    open(path, "w", encoding="utf-8").write(f"""<!doctype html><meta charset=utf-8><title>AegisNet report</title>
<style>body{{background:#0A0F1F;color:#E8EEFF;font:16px/1.5 Calibri,Arial,sans-serif;max-width:1000px;margin:auto;padding:24px}}
h1{{color:#00F0C8}}h2{{color:#FFB020;margin-top:32px}}img{{max-width:100%;border-radius:10px}}
.g{{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px}}
.c{{background:#121B33;border-radius:12px;padding:14px}}.c b{{display:block;font-size:26px;color:#00F0C8}}.c span{{color:#7F8DB3;font-size:13px}}
pre{{background:#121B33;padding:14px;border-radius:10px;white-space:pre-wrap;color:#E8EEFF}}</style>
<h1>AegisNet - test report</h1><p>Generated automatically by <code>python run_all.py</code>. Data is simulated telemetry.</p>
<div class=g>{cards}</div>{imgs}<h2>Guardian-agent incident reports</h2>{inc}""")
