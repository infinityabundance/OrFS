#!/usr/bin/env python3
"""Render self-contained SVG charts from the machine-generated evidence receipts.

Pure Python 3 standard library only: it reads JSON receipts under
``evidence/performance/`` and writes small, deterministic, inline-styled SVG
files under ``docs/charts/``.  There are no external fonts, no JavaScript, no
network access, and no timestamps, so a re-run is byte-identical (that is what
makes ``--check`` meaningful).

Usage:
    python3 scripts/render_charts.py            # (re)generate every chart
    python3 scripts/render_charts.py --check     # regenerate in memory and
                                                 # compare against the committed
                                                 # files; exit 1 on any drift
    python3 scripts/render_charts.py --list      # chart -> receipt mapping

The mapping of every committed image to its source receipt and its exact
command lives in ``docs/REPRODUCE.md`` ("Images and charts").
"""

import argparse
import json
import math
import os
import sys
from xml.sax.saxutils import escape

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EVIDENCE = os.path.join(ROOT, "evidence", "performance")
OUTDIR = os.path.join(ROOT, "docs", "charts")

# A fixed palette; index-stable so the output never depends on dict ordering.
PALETTE = (
    "#1f77b4", "#d62728", "#2ca02c", "#ff7f0e",
    "#9467bd", "#8c564b", "#17becf", "#7f7f7f",
)

# Canvas and plot geometry.  Kept small: 760x440, no external assets.
W, H = 760, 440
PAD_L, PAD_R, PAD_T, PAD_B = 84, 24, 62, 100
PX0, PX1 = PAD_L, W - PAD_R
PY0, PY1 = PAD_T, H - PAD_B
PLOT_W, PLOT_H = PX1 - PX0, PY1 - PY0

BG = "#ffffff"
AXIS = "#333333"
GRID = "#e8e8e8"
TEXT = "#111111"
MUTED = "#555555"


# --------------------------------------------------------------------------
# small formatting / SVG helpers (all deterministic)
# --------------------------------------------------------------------------

def esc(value):
    return escape(str(value))


def compact(v):
    """A short human label for an axis tick value (no locale dependence)."""
    if v is None:
        return ""
    if isinstance(v, str):
        return v
    a = abs(v)
    if a == 0:
        return "0"
    if a >= 1e9:
        return "{:g}G".format(v / 1e9)
    if a >= 1e6:
        return "{:g}M".format(v / 1e6)
    if a >= 1e3:
        return "{:g}k".format(v / 1e3)
    if a >= 1:
        return "{:g}".format(v)
    if a >= 0.01:
        return "{:.2f}".format(v)
    return "{:.4g}".format(v)


def line(x1, y1, x2, y2, color, width):
    return '<line x1="{:.1f}" y1="{:.1f}" x2="{:.1f}" y2="{:.1f}" stroke="{}" stroke-width="{}"/>'.format(
        x1, y1, x2, y2, color, width)


def text(x, y, s, color=TEXT, size=11, anchor="start", weight=None):
    w = ' font-weight="bold"' if weight else ""
    return '<text x="{:.1f}" y="{:.1f}" fill="{}" font-size="{}" text-anchor="{}"{}>{}</text>'.format(
        x, y, color, size, anchor, w, esc(s))


def rot_text(x, y, s, color=TEXT, size=12):
    return '<text x="{:.1f}" y="{:.1f}" fill="{}" font-size="{}" text-anchor="middle" transform="rotate(-90 {:.1f} {:.1f})">{}</text>'.format(
        x, y, color, size, x, y, esc(s))


def svg_header(title):
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" width="{}" height="{}" '
        'viewBox="0 0 {} {}" font-family="monospace">'.format(W, H, W, H)
        + '<rect x="0" y="0" width="{}" height="{}" fill="{}"/>'.format(W, H, BG)
        + text(W / 2.0, 22, title, TEXT, 14, "middle", weight=True)
    )


def legend(entries, y=44):
    """A single horizontal legend row inside the top margin."""
    out = []
    x = PX0
    for i, name in enumerate(entries):
        col = PALETTE[i % len(PALETTE)]
        out.append('<rect x="{:.1f}" y="{:.1f}" width="10" height="10" fill="{}"/>'.format(
            x, y - 9, col))
        out.append(text(x + 15, y, name, TEXT, 11, "start"))
        x += 15 + 7 * len(str(name)) + 20
    return "\n".join(out)


def caption(lines):
    out = []
    y = H - 70
    for ln in lines:
        out.append(text(PX0, y, ln, MUTED, 10))
        y += 16
    return "\n".join(out)


class Scale(object):
    def __init__(self, lo, hi, p0, p1, log=False):
        self.log = log
        if log:
            self.lo = math.log10(lo)
            self.hi = math.log10(hi)
        else:
            self.lo = lo
            self.hi = hi
        if self.hi == self.lo:
            self.hi = self.lo + 1.0
        self.p0 = p0
        self.p1 = p1

    def pos(self, v):
        if self.log:
            v = math.log10(v)
        t = (v - self.lo) / (self.hi - self.lo)
        return self.p0 + t * (self.p1 - self.p0)


def log_bounds(vals):
    pos = [v for v in vals if v is not None and v > 0]
    lo = 10.0 ** math.floor(math.log10(min(pos)))
    hi = 10.0 ** math.ceil(math.log10(max(pos)))
    if hi == lo:
        hi = lo * 10.0
    return lo, hi


def log_ticks(lo, hi):
    ticks = []
    e = int(round(math.log10(lo)))
    while 10.0 ** e <= hi * (1 + 1e-9):
        v = 10.0 ** e
        if v >= lo * (1 - 1e-9):
            ticks.append(v)
        e += 1
    return ticks


def lin_ticks(lo, hi, n=5):
    if hi == lo:
        hi = lo + 1.0
    raw = (hi - lo) / float(n)
    mag = 10.0 ** math.floor(math.log10(raw))
    step = 10.0 * mag
    for m in (1, 2, 2.5, 5, 10):
        if raw <= m * mag:
            step = m * mag
            break
    start = math.ceil(lo / step) * step
    ticks = []
    v = start
    while v <= hi + step * 1e-9:
        ticks.append(v)
        v += step
    return ticks


def frame(parts, xs, ys, xlabel, ylabel, yticks, xticks):
    for t in yticks:
        y = ys.pos(t)
        parts.append(line(PX0, y, PX1, y, GRID, 1))
        parts.append(text(PX0 - 8, y + 4, compact(t), TEXT, 11, "end"))
    for t in xticks:
        x = xs.pos(t)
        parts.append(line(x, PY0, x, PY1, GRID, 1))
        parts.append(text(x, PY1 + 18, compact(t), TEXT, 11, "middle"))
    parts.append(line(PX0, PY0, PX0, PY1, AXIS, 1.5))
    parts.append(line(PX0, PY1, PX1, PY1, AXIS, 1.5))
    parts.append(text((PX0 + PX1) / 2.0, PY1 + 42, xlabel, TEXT, 12, "middle"))
    parts.append(rot_text(PX0 - 58, (PY0 + PY1) / 2.0, ylabel, TEXT, 12))


def line_chart(title, caption_lines, xlabel, ylabel, series,
               xlog=False, ylog=False, xticks=None, ymin=None, ymax=None):
    xs_all = [p[0] for s in series for p in s["points"]]
    ys_all = [p[1] for s in series for p in s["points"]]
    if xlog:
        xlo, xhi = log_bounds(xs_all)
    else:
        xlo, xhi = min(xs_all), max(xs_all)
        if xlo == xhi:
            xhi = xlo + 1.0
    if ylog:
        ylo, yhi = log_bounds(ys_all)
    else:
        ylo = ymin if ymin is not None else min(ys_all)
        yhi = ymax if ymax is not None else max(ys_all)
        if ylo == yhi:
            yhi = ylo + 1.0
    xs = Scale(xlo, xhi, PX0, PX1, xlog)
    ys = Scale(ylo, yhi, PY1, PY0, ylog)
    ytk = log_ticks(ylo, yhi) if ylog else lin_ticks(ylo, yhi)
    xtk = xticks if xticks is not None else (log_ticks(xlo, xhi) if xlog else lin_ticks(xlo, xhi))
    parts = [svg_header(title)]
    frame(parts, xs, ys, xlabel, ylabel, ytk, xtk)
    for i, s in enumerate(series):
        col = PALETTE[i % len(PALETTE)]
        pts = " ".join("{:.1f},{:.1f}".format(xs.pos(px), ys.pos(py)) for px, py in s["points"])
        parts.append('<polyline points="{}" fill="none" stroke="{}" stroke-width="2"/>'.format(pts, col))
        for px, py in s["points"]:
            parts.append('<circle cx="{:.1f}" cy="{:.1f}" r="3" fill="{}"/>'.format(
                xs.pos(px), ys.pos(py), col))
    parts.append(legend([s["name"] for s in series]))
    parts.append(caption(caption_lines))
    parts.append("</svg>")
    return "\n".join(parts)


def bar_chart(title, caption_lines, ylabel, groups, series, ymin=None, ymax=None):
    allv = [v for s in series for v in s["values"] if v is not None]
    ylo = ymin if ymin is not None else 0.0
    yhi = ymax if ymax is not None else max(allv)
    if yhi == ylo:
        yhi = ylo + 1.0
    ys = Scale(ylo, yhi, PY1, PY0, False)
    parts = [svg_header(title)]
    # y ticks / gridlines + y label (no x tick helper needed for categories)
    for t in lin_ticks(ylo, yhi):
        y = ys.pos(t)
        parts.append(line(PX0, y, PX1, y, GRID, 1))
        parts.append(text(PX0 - 8, y + 4, compact(t), TEXT, 11, "end"))
    parts.append(line(PX0, PY0, PX0, PY1, AXIS, 1.5))
    parts.append(line(PX0, PY1, PX1, PY1, AXIS, 1.5))
    parts.append(rot_text(PX0 - 58, (PY0 + PY1) / 2.0, ylabel, TEXT, 12))
    n = len(groups)
    m = len(series)
    gw = PLOT_W / float(n)
    bw = gw * 0.8 / m
    for gi, g in enumerate(groups):
        gx = PX0 + gi * gw + gw * 0.1
        for si, s in enumerate(series):
            v = s["values"][gi]
            if v is None:
                continue
            col = PALETTE[si % len(PALETTE)]
            x = gx + si * bw + bw * 0.1
            w = bw * 0.8
            y = ys.pos(v)
            h = PY1 - y
            parts.append('<rect x="{:.1f}" y="{:.1f}" width="{:.1f}" height="{:.1f}" fill="{}"/>'.format(
                x, y, w, h, col))
        parts.append(text(PX0 + gi * gw + gw / 2.0, PY1 + 18, g, TEXT, 11, "middle"))
    parts.append(legend([s["name"] for s in series]))
    parts.append(caption(caption_lines))
    parts.append("</svg>")
    return "\n".join(parts)


# --------------------------------------------------------------------------
# receipt loading
# --------------------------------------------------------------------------

def load(name):
    path = os.path.join(EVIDENCE, name)
    with open(path, "r") as fh:
        return json.load(fh)


# --------------------------------------------------------------------------
# chart builders
# --------------------------------------------------------------------------

def chart_history_scaling():
    d = load("history-scaling.json")
    auth = d["arms"]["authoritative"]["checkpoints"]
    man = d["arms"]["manifested"]["checkpoints"]
    ep = [c["epoch"] for c in auth]

    def col(cps, key):
        return [(c["epoch"], c["workload"][key]) for c in cps]

    series = [
        {"name": "auth p50", "points": col(auth, "p50_ns")},
        {"name": "auth p99", "points": col(auth, "p99_ns")},
        {"name": "man p50", "points": col(man, "p50_ns")},
        {"name": "man p99", "points": col(man, "p99_ns")},
    ]
    cap = [
        "source: evidence/performance/history-scaling.json (epochs %s)" % ",".join(str(e) for e in ep),
        "same fixed read workload at each checkpoint; log y-axis",
        "regenerate: python3 scripts/render_charts.py --check",
    ]
    return line_chart(
        "history-scaling: read latency vs. growing history",
        cap, "checkpoint epoch", "read latency (ns, log)", series,
        xlog=False, ylog=True, xticks=ep)


def chart_history_scaling_bytes():
    d = load("history-scaling.json")
    auth = d["arms"]["authoritative"]["checkpoints"]
    man = d["arms"]["manifested"]["checkpoints"]
    ep = [c["epoch"] for c in auth]
    mib = 1024.0 * 1024.0
    series = [
        {"name": "auth m_total",
         "points": [(c["epoch"], c["physical"]["m_total"] / mib) for c in auth]},
        {"name": "man m_total",
         "points": [(c["epoch"], c["physical"]["m_total"] / mib) for c in man]},
    ]
    cap = [
        "source: evidence/performance/history-scaling.json (m_total, both arms)",
        "persistent bytes from retained history; the 1e9-inode long-endurance curve is deferred",
        "regenerate: python3 scripts/render_charts.py --check",
    ]
    return line_chart(
        "history-scaling: persistent bytes vs. retained history",
        cap, "checkpoint epoch", "persistent physical bytes (MiB, log)", series,
        xlog=False, ylog=True, xticks=ep)


def chart_manifestation_catalogue():
    d = load("manifestation-catalogue.json")
    cps = d["checkpoints"]
    g = [c["generations"] for c in cps]
    series = [
        {"name": "publish p50",
         "points": [(c["generations"], c["publication"]["p50_ns"] / 1000.0) for c in cps]},
        {"name": "fast recovery",
         "points": [(c["generations"], c["recovery"]["fast_micros"]) for c in cps]},
        {"name": "full-scan recovery",
         "points": [(c["generations"], c["recovery"]["full_scan_micros"]) for c in cps]},
    ]
    cap = [
        "source: evidence/performance/manifestation-catalogue.json (inodes=64)",
        "publication is flat in G; fast recovery is suffix-proportional;",
        "full-scan recovery is linear in G and host-load sensitive",
        "regenerate: python3 scripts/render_charts.py --check",
    ]
    return line_chart(
        "append-only catalogue: publication and recovery vs. generations",
        cap, "committed generations G (log)", "time (us, log)", series,
        xlog=True, ylog=True)


def chart_planner_cache():
    d = load("planner-cache.json")
    meas = d["measured"]
    fifo = d["fifo_model"]
    groups = ["cold scan rebuilds", "steady hot rebuilds"]
    series = [
        {"name": "AdmissionCache", "values": [meas["scan_plan_builds"], meas["hot_only_plan_builds"]]},
        {"name": "FIFO model", "values": [fifo["scan_plan_builds"], fifo["hot_only_plan_builds"]]},
    ]
    cap = [
        "source: evidence/performance/planner-cache.json (capacity 32, scan 512)",
        "body-plan rebuilds over the identical key trace;",
        "the FIFO row is an analytic model, not a second run",
        "regenerate: python3 scripts/render_charts.py --check",
    ]
    return bar_chart(
        "volatile planner caches: scan resistance (body-plan rebuilds)",
        cap, "body-plan rebuilds", groups, series)


def chart_microarch():
    d = load("microarch.json")
    curve = d["pmap_lookup_curve"]
    series = [{"name": "PMap lookup",
               "points": [(c["entries"], c["ns_per_lookup"]) for c in curve]}]
    cap = [
        "source: evidence/performance/microarch.json (pmap_lookup_curve)",
        "working-set sweep of PMap point lookups; a cache-hierarchy proxy",
        "(a shape here, not PMU-attributed in this default-container run)",
        "regenerate: python3 scripts/render_charts.py --check",
    ]
    return line_chart(
        "PMap point lookup vs. working set (cache-hierarchy proxy)",
        cap, "PMap entries (log)", "lookup latency (ns)", series, xlog=True, ylog=False)


def chart_search_directory():
    d = load("search-directory.json")
    patterns = [
        ("616263", "abc"), ("7a7a71", "zzq"), ("6d6d6d", "mmm"),
    ]
    by = {}
    for path_name, key in (("indexed", "indexed_path"), ("directory", "directory_path"),
                           ("scan", "full_scan")):
        by[path_name] = {row["pattern_hex"]: row["files_considered"] for row in d[key]}
    groups = [lbl for _, lbl in patterns]
    series = [
        {"name": "indexed", "values": [by["indexed"][h] for h, _ in patterns]},
        {"name": "directory", "values": [by["directory"][h] for h, _ in patterns]},
        {"name": "full scan", "values": [by["scan"][h] for h, _ in patterns]},
    ]
    cap = [
        "source: evidence/performance/search-directory.json (2048 files, 522 keys)",
        "files considered per pattern: abc=common, zzq=rare (8 objects), mmm=absent;",
        "8 vs 2048 on zzq is the 256x file-enumeration reduction",
        "regenerate: python3 scripts/render_charts.py --check",
    ]
    return bar_chart(
        "global search directory: files considered per query path",
        cap, "files considered", groups, series)


def chart_baselines():
    d = load("baselines.json")
    res = d["results"]

    def find(backend, workload):
        for r in res:
            if r["backend"] == backend and r["workload"] == workload:
                return r["measurement"].get("mb_per_s")
        return None

    backends = [b["name"] for b in d["backends"]]
    groups = backends + ["raw-memory"]
    series = [
        {"name": "seq append MB/s",
         "values": [find(b, "sequential-append") for b in backends] + [None]},
        {"name": "seq read MB/s",
         "values": [find(b, "sequential-read") for b in backends]
                   + [d["raw_memory_read"]["mb_per_s"]]},
    ]
    cap = [
        "source: evidence/performance/baselines.json (32 MiB file, page-cache warm)",
        "raw-memory is a Vec<u8> scan (read only); these are the external floor, not an OrFS win",
        "regenerate: python3 scripts/render_charts.py --check",
    ]
    return bar_chart(
        "external baselines: sequential throughput by backend",
        cap, "throughput (MB/s)", groups, series)


def chart_baselines_latency():
    d = load("baselines.json")
    res = d["results"]

    def find(backend, workload):
        for r in res:
            if r["backend"] == backend and r["workload"] == workload:
                return r["measurement"]["latency"]
        return None

    backends = [b["name"] for b in d["backends"]]

    def lat(b, wl, key):
        l = find(b, wl)
        return None if l is None else l[key]

    series = [
        {"name": "4K p50", "values": [lat(b, "random-read-4k", "p50_ns") for b in backends]},
        {"name": "4K p99", "values": [lat(b, "random-read-4k", "p99_ns") for b in backends]},
        {"name": "1B p50", "values": [lat(b, "random-read-1", "p50_ns") for b in backends]},
        {"name": "1B p99", "values": [lat(b, "random-read-1", "p99_ns") for b in backends]},
    ]
    cap = [
        "source: evidence/performance/baselines.json (20000 random ops, page-cache warm)",
        "warm random-read latency per backend; OrFS's daemon path is not faster",
        "than these (see PERFORMANCE.md 20)",
        "regenerate: python3 scripts/render_charts.py --check",
    ]
    return bar_chart(
        "external baselines: warm random-read latency by backend",
        cap, "latency (ns)", backends, series)


def chart_uring_depth():
    d = load("uring-depth.json")
    rows = d["rows"]
    series = [
        {"name": "read MB/s",
         "points": [(r["requested_depth"], r["read"]["mb_per_s"]) for r in rows]},
        {"name": "write MB/s",
         "points": [(r["requested_depth"], r["write"]["mb_per_s"]) for r in rows]},
    ]
    depths = [r["requested_depth"] for r in rows]
    cap = [
        "source: evidence/performance/uring-depth.json (32 rounds x 128 x 4 KiB per depth)",
        "x is the requested depth; depth 1 rounds up to a ring of 2 (UringEngine floor)",
        "regenerate: python3 scripts/render_charts.py --check",
    ]
    return line_chart(
        "io_uring depth sweep: batched positional throughput",
        cap, "requested ring depth (log)", "throughput (MB/s)", series,
        xlog=True, ylog=False, xticks=depths)


def chart_uring_depth_sq():
    d = load("uring-depth.json")
    rows = d["rows"]
    series = [
        {"name": "read sq_full",
         "points": [(r["requested_depth"], r["read"]["stats"]["sq_full_events"]) for r in rows]},
        {"name": "write sq_full",
         "points": [(r["requested_depth"], r["write"]["stats"]["sq_full_events"]) for r in rows]},
    ]
    depths = [r["requested_depth"] for r in rows]
    cap = [
        "source: evidence/performance/uring-depth.json (read.stats/write.stats.sq_full_events)",
        "read_batch overflows the SQ at small depths;",
        "write_batch caps its chunk at the depth, so it never does",
        "regenerate: python3 scripts/render_charts.py --check",
    ]
    return line_chart(
        "io_uring depth sweep: submission-queue backpressure",
        cap, "requested ring depth (log)", "SQ-full events", series,
        xlog=True, ylog=False, xticks=depths)


def chart_reader_scaling_64():
    d = load("reader-scaling-64.json")
    res = d["results"]
    series = [{"name": "aggregate",
               "points": [(r["readers"], r["ops_per_s"]) for r in res]}]
    readers = [r["readers"] for r in res]
    cap = [
        "source: evidence/performance/reader-scaling-64.json (one shared ReadPlanner)",
        "peaks at 4 readers (~8.0 M ops/s) then falls; container CFS-capped at 8 CPUs",
        "regenerate: python3 scripts/render_charts.py --check",
    ]
    return line_chart(
        "concurrent read scaling: aggregate throughput",
        cap, "concurrent readers (log)", "aggregate throughput (ops/s)", series,
        xlog=True, ylog=False, xticks=readers)


def chart_reader_scaling_64_tail():
    d = load("reader-scaling-64.json")
    res = d["results"]
    series = [
        {"name": "p50", "points": [(r["readers"], r["p50_ns"]) for r in res]},
        {"name": "p95", "points": [(r["readers"], r["p95_ns"]) for r in res]},
        {"name": "p99", "points": [(r["readers"], r["p99_ns"]) for r in res]},
        {"name": "p99.9", "points": [(r["readers"], r["p999_ns"]) for r in res]},
    ]
    readers = [r["readers"] for r in res]
    cap = [
        "source: evidence/performance/reader-scaling-64.json (pooled per-op samples)",
        "the tail (p99.9 300 ns -> 201 us) is where the shared-lock wait shows;",
        "p50 rises only 181 -> 1593 ns across 1..64 readers",
        "regenerate: python3 scripts/render_charts.py --check",
    ]
    return line_chart(
        "concurrent read scaling: latency percentiles",
        cap, "concurrent readers (log)", "latency (ns, log)", series,
        xlog=True, ylog=True, xticks=readers)


def chart_pmu():
    d = load("pmu.json")
    comps = d["components"]
    labels = {
        "pmap_point_lookup": "pmap",
        "ekbloom_manifested_read": "ekbloom",
        "readplanner_steady_state_selection": "planner",
        "backing_log_segment_read": "backing",
    }
    groups = [labels.get(c["name"], c["name"]) for c in comps]
    series = [
        {"name": "cycles/op", "values": [c["per_op"]["cycles"] for c in comps]},
        {"name": "instructions/op", "values": [c["per_op"]["instructions"] for c in comps]},
    ]
    cap = [
        "source: evidence/performance/pmu.json (release, one thread, --cap-add PERFMON)",
        "per-op hardware counters: pmap is cache-miss-bound (IPC 0.30);",
        "the manifested read/planner paths are instruction-bound (IPC 3.45-3.98)",
        "regenerate: python3 scripts/render_charts.py --check",
    ]
    return bar_chart(
        "PMU counters per hot-path component (IPC = insn/cycle)",
        cap, "per-op count", groups, series)


# --------------------------------------------------------------------------
# registry: file name -> (builder, source receipt, generating command)
# --------------------------------------------------------------------------

CHARTS = (
    ("history-scaling.svg", chart_history_scaling,
     "evidence/performance/history-scaling.json", "sh scripts/container-history-scaling.sh"),
    ("history-scaling-bytes.svg", chart_history_scaling_bytes,
     "evidence/performance/history-scaling.json", "sh scripts/container-history-scaling.sh"),
    ("manifestation-catalogue.svg", chart_manifestation_catalogue,
     "evidence/performance/manifestation-catalogue.json", "sh scripts/container-manifestation-catalogue.sh"),
    ("planner-cache.svg", chart_planner_cache,
     "evidence/performance/planner-cache.json", "sh scripts/container-planner-cache.sh"),
    ("microarch.svg", chart_microarch,
     "evidence/performance/microarch.json", "sh scripts/container-microarch.sh"),
    ("search-directory.svg", chart_search_directory,
     "evidence/performance/search-directory.json", "sh scripts/container-search-directory.sh"),
    ("baselines.svg", chart_baselines,
     "evidence/performance/baselines.json", "sh scripts/container-baseline.sh"),
    ("baselines-latency.svg", chart_baselines_latency,
     "evidence/performance/baselines.json", "sh scripts/container-baseline.sh"),
    ("uring-depth.svg", chart_uring_depth,
     "evidence/performance/uring-depth.json", "sh scripts/container-uring-depth.sh"),
    ("uring-depth-sq.svg", chart_uring_depth_sq,
     "evidence/performance/uring-depth.json", "sh scripts/container-uring-depth.sh"),
    ("reader-scaling-64.svg", chart_reader_scaling_64,
     "evidence/performance/reader-scaling-64.json", "sh scripts/container-reader-scale64.sh"),
    ("reader-scaling-64-tail.svg", chart_reader_scaling_64_tail,
     "evidence/performance/reader-scaling-64.json", "sh scripts/container-reader-scale64.sh"),
    ("pmu.svg", chart_pmu,
     "evidence/performance/pmu.json", "sh scripts/container-pmu.sh"),
)


def render_all():
    """Return a list of (filename, svg_text) rendered fully in memory."""
    out = []
    for fname, builder, _, _ in CHARTS:
        out.append((fname, builder()))
    return out


def do_generate():
    if not os.path.isdir(OUTDIR):
        os.makedirs(OUTDIR)
    for fname, svg in render_all():
        path = os.path.join(OUTDIR, fname)
        with open(path, "w", newline="\n") as fh:
            fh.write(svg)
        print("wrote docs/charts/{} ({} bytes)".format(fname, len(svg.encode("utf-8"))))
    return 0


def do_check():
    drift = []
    for fname, svg in render_all():
        path = os.path.join(OUTDIR, fname)
        if not os.path.isfile(path):
            drift.append((fname, "missing (not committed)"))
            continue
        with open(path, "rb") as fh:
            committed = fh.read()
        if committed != svg.encode("utf-8"):
            drift.append((fname, "differs from regenerated output"))
    if drift:
        print("check-docs-charts: DRIFT ({})".format(len(drift)))
        for fname, why in drift:
            print("  docs/charts/{}: {}".format(fname, why))
        print("run: python3 scripts/render_charts.py  and commit the result")
        return 1
    print("check-docs-charts: OK ({} charts match the receipts)".format(len(CHARTS)))
    return 0


def do_list():
    for fname, _, receipt, cmd in CHARTS:
        print("{}\n  receipt: {}\n  cmd:     {}".format(fname, receipt, cmd))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true",
                    help="regenerate in memory and compare against docs/charts/")
    ap.add_argument("--list", action="store_true",
                    help="print the chart -> receipt -> command mapping")
    args = ap.parse_args(argv)
    if args.check:
        return do_check()
    if args.list:
        return do_list()
    return do_generate()


if __name__ == "__main__":
    sys.exit(main())
