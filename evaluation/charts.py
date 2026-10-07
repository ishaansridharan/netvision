"""
Report figures for the evaluation (evaluation/charts.py)

Static vs adaptive is a two-series comparison, so every chart uses the
first two categorical slots (blue = static, orange = adaptive; validated
for colour-vision deficiency in light mode) with a legend.  Different
measures never share an axis: precision/recall/F1 (0–1), false-positive
rate (%) and detection latency (s) are separate figures.  Every number in
a figure is also in metrics.csv.
"""

from __future__ import annotations

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import FancyBboxPatch, Rectangle  # noqa: E402

SURFACE = "#fcfcfb"
INK = "#0b0b0b"
INK_2 = "#52514e"
MUTED = "#898781"
GRID = "#e1e0d9"
AXIS = "#c3c2b7"
WASH = "#f0efec"
SERIES = {"static": "#2a78d6", "adaptive": "#eb6834"}
LABEL = {"static": "Static thresholds", "adaptive": "Adaptive (EWMA + flow context)"}
TYPE_LABEL = {
    "PORT_SCAN": "Port scan", "SYN_FLOOD": "SYN flood",
    "ARP_ANOMALY": "ARP anomaly", "TRAFFIC_SPIKE": "Traffic spike", "ALL": "All types",
}

BAR_PX = 22      # ≤ 24 px thick
GAP_PX = 2       # surface gap between adjacent bars
RADIUS_PX = 4    # rounded data-end


def _style() -> None:
    plt.rcParams.update({
        "figure.facecolor": SURFACE, "axes.facecolor": SURFACE, "savefig.facecolor": SURFACE,
        "font.family": "sans-serif",
        "font.sans-serif": ["Inter", "Segoe UI", "Helvetica", "Arial", "DejaVu Sans"],
        "font.size": 10, "text.color": INK, "axes.labelcolor": INK_2,
        "xtick.color": MUTED, "ytick.color": MUTED,
        "axes.edgecolor": AXIS, "axes.linewidth": 1.0,
        "axes.spines.top": False, "axes.spines.right": False, "axes.spines.left": False,
        "axes.grid": True, "axes.grid.axis": "y", "grid.color": GRID,
        "grid.linewidth": 0.8, "grid.linestyle": "-",
        "axes.titleweight": "bold", "axes.titlesize": 12, "axes.titlelocation": "left",
        "legend.frameon": False,
    })


def _px_to_data(ax, px_x: float, px_y: float) -> tuple[float, float]:
    inv = ax.transData.inverted()
    x0, y0 = inv.transform((0, 0))
    x1, y1 = inv.transform((px_x, px_y))
    return abs(x1 - x0), abs(y1 - y0)


def _hbar(ax, y_center: float, length: float, thickness: float, color: str) -> None:
    """Horizontal bar: 4 px rounded data-end on the right, square at the baseline."""
    if length <= 0:
        return
    rx, ry = _px_to_data(ax, RADIUS_PX, RADIUS_PX)
    y = y_center - thickness / 2
    ax.add_patch(FancyBboxPatch(
        (0, y), length, thickness,
        boxstyle=f"round,pad=0,rounding_size={min(ry, thickness / 2)}",
        mutation_aspect=rx / ry if ry else 1, facecolor=color, edgecolor="none", zorder=3,
    ))
    ax.add_patch(Rectangle((0, y), min(length, rx), thickness, facecolor=color,
                           edgecolor="none", zorder=3))


def _grouped(ax, groups: list[str], values: dict[str, list], fmt, xmax: float) -> None:
    """
    One row per group, a static and an adaptive bar per row (2 px apart),
    each value at its bar's tip — horizontal so adjacent labels never collide.
    """
    n = len(groups)
    ax.set_ylim(n - 0.4, -0.6)          # first group at the top
    ax.set_xlim(0, xmax)
    ax.grid(axis="y", visible=False)
    ax.grid(axis="x", visible=True)
    ax.spines["left"].set_visible(True)
    ax.spines["bottom"].set_visible(False)
    ax.figure.canvas.draw()
    _, bar_h = _px_to_data(ax, 0, BAR_PX * 0.8)
    _, gap = _px_to_data(ax, 0, GAP_PX)
    pad, _ = _px_to_data(ax, 6, 0)
    for gi in range(n):
        for si, mode in enumerate(("static", "adaptive")):
            v = values[mode][gi]
            yc = gi + (si - 0.5) * (bar_h + gap)
            if v is None:
                ax.text(pad, yc, "n/a", va="center", fontsize=8, color=MUTED)
                continue
            _hbar(ax, yc, v, bar_h, SERIES[mode])
            ax.text(v + pad, yc, fmt(v), va="center", fontsize=8, color=INK_2, zorder=4)
    ax.set_yticks(range(n), groups)
    ax.tick_params(axis="y", length=0, colors=INK_2)
    ax.tick_params(axis="x", length=0)
    ax.set_axisbelow(True)


def thousands(ax, axis: str = "both") -> None:
    from matplotlib.ticker import FuncFormatter
    fmt = FuncFormatter(lambda v, _: f"{v:,.0f}")
    if axis in ("x", "both"):
        ax.xaxis.set_major_formatter(fmt)
    if axis in ("y", "both"):
        ax.yaxis.set_major_formatter(fmt)


def _legend(fig) -> None:
    handles = [Rectangle((0, 0), 1, 1, facecolor=SERIES[m]) for m in ("static", "adaptive")]
    fig.legend(handles, [LABEL["static"], LABEL["adaptive"]], loc="upper right",
               ncol=2, fontsize=9, handlelength=1.0, handleheight=1.0,
               bbox_to_anchor=(0.98, 0.98))


def quality_chart(results: dict, path: str) -> None:
    """Precision, recall and F1 over all attack types."""
    _style()
    fig, ax = plt.subplots(figsize=(7, 3.4), dpi=150)
    metrics = ["precision", "recall", "f1"]
    vals = {m: [results[m]["overall"][k] for k in metrics] for m in ("static", "adaptive")}
    _grouped(ax, ["Precision", "Recall", "F1-score"], vals, lambda v: f"{v:.2f}", 1.12)
    ax.set_xticks([0, 0.25, 0.5, 0.75, 1.0])
    ax.set_title("Detection quality, all attack types")
    _legend(fig)
    fig.tight_layout(rect=(0, 0, 1, 0.9))
    fig.savefig(path)
    plt.close(fig)


def fpr_chart(results: dict, path: str) -> None:
    """False-positive rate per detector (share of normal 10 s bins with an alert)."""
    _style()
    types = ["PORT_SCAN", "SYN_FLOOD", "ARP_ANOMALY", "TRAFFIC_SPIKE"]
    vals = {
        m: [_pct(results[m]["per_type"][t]["fpr"]) for t in types] + [_pct(results[m]["overall"]["fpr"])]
        for m in ("static", "adaptive")
    }
    top = max([v for vs in vals.values() for v in vs if v is not None] + [1.0])
    fig, ax = plt.subplots(figsize=(8, 4.2), dpi=150)
    _grouped(ax, [TYPE_LABEL[t] for t in types] + ["Any detector"], vals,
             lambda v: f"{v:.1f}%", top * 1.2)
    ax.set_xlabel("Normal 10-second bins containing an alert (%)")
    ax.set_title("False-positive rate (lower is better)")
    _legend(fig)
    fig.tight_layout(rect=(0, 0, 1, 0.9))
    fig.savefig(path)
    plt.close(fig)


def latency_chart(results: dict, path: str) -> None:
    """Median detection latency per attack type."""
    _style()
    types = [t for t in ("PORT_SCAN", "SYN_FLOOD", "ARP_ANOMALY", "TRAFFIC_SPIKE")
             if results["static"]["per_type"][t]["incidents"]]
    if not types:
        return
    vals = {m: [results[m]["per_type"][t]["latency_median_s"] for t in types]
            for m in ("static", "adaptive")}
    top = max([v for vs in vals.values() for v in vs if v is not None] + [1.0])
    fig, ax = plt.subplots(figsize=(7, 1.4 + 0.75 * len(types)), dpi=150)
    _grouped(ax, [TYPE_LABEL[t] for t in types], vals, lambda v: f"{v:.1f} s", top * 1.2)
    ax.set_xlabel("Seconds from attack start")
    ax.set_title("Median detection latency (lower is better; n/a = missed)")
    _legend(fig)
    fig.tight_layout(rect=(0, 0, 1, 0.9))
    fig.savefig(path)
    plt.close(fig)


def timeline_chart(case: dict, path: str) -> None:
    """
    Two panels on a shared time axis: throughput (one series) with labelled
    incident windows, and one lane of alert markers per detection mode.
    """
    _style()
    t0 = case["t_start"]
    series = case["throughput"]   # [(ts, bytes_per_s)]
    fig, (ax1, ax2) = plt.subplots(
        2, 1, figsize=(10, 4.6), dpi=150, sharex=True,
        gridspec_kw={"height_ratios": [3, 1.2], "hspace": 0.08},
    )

    for inc in case["incidents"]:
        for ax in (ax1, ax2):
            ax.axvspan(inc["start"] - t0, inc["end"] - t0, color=WASH, zorder=0, lw=0)
        ax1.text((inc["start"] - t0), 1.0, TYPE_LABEL.get(inc["type"], inc["type"]),
                 transform=ax1.get_xaxis_transform(), fontsize=8, color=INK_2,
                 va="bottom", ha="left")

    xs = [ts - t0 for ts, _ in series]
    ys = [b * 8 / 1e6 for _, b in series]
    # Context series in neutral ink: blue/orange mean static/adaptive in this figure.
    ax1.plot(xs, ys, color=INK_2, lw=1.5,
             solid_joinstyle="round", solid_capstyle="round", zorder=2)
    ax1.fill_between(xs, ys, color=INK_2, alpha=0.10, lw=0, zorder=1)
    ax1.set_ylabel("Mbit/s")
    ax1.set_ylim(bottom=0)
    ax1.set_title(f"{case['name']}: throughput, labelled incidents and alerts", pad=16)

    lanes = {"static": 1, "adaptive": 0}
    for mode, y in lanes.items():
        pts = [a["timestamp"] - t0 for a in case["alerts"][mode]]
        ax2.scatter(pts, [y] * len(pts), s=36, color=SERIES[mode],
                    edgecolors=SURFACE, linewidths=2, zorder=3, label=LABEL[mode])
    ax2.set_yticks([1, 0], ["Static", "Adaptive"])
    ax2.set_ylim(-0.6, 1.6)
    ax2.grid(False)
    ax2.tick_params(axis="y", length=0, colors=INK_2)
    ax2.set_xlabel("Seconds from start of capture")
    _legend(fig)
    fig.subplots_adjust(left=0.08, right=0.98, top=0.86, bottom=0.12)
    fig.savefig(path)
    plt.close(fig)


def _pct(v):
    return v * 100 if v is not None else None
