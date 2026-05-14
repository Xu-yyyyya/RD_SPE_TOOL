#!/usr/bin/env python3
"""Plot targeted-RD log2 histogram files as normalized proportions."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Dict, Iterable, Tuple

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import PercentFormatter


Bucket = Tuple[int, int]
OUT_DIR = Path(__file__).resolve().parent / "out"


def resolve_output_path(path: Path) -> Path:
    if path.is_absolute():
        return path
    return OUT_DIR / path


def bucket_for_delta(delta: int) -> Bucket:
    if delta <= 0:
        return (0, 0)
    if delta == 1:
        return (1, 1)
    lo = 1 << (delta.bit_length() - 1)
    return (lo, (lo << 1) - 1)


def log2_buckets_through(delta: int) -> list[Bucket]:
    buckets = [(0, 0), (1, 1)]
    lo = 2
    target = max(1, delta)
    while True:
        hi = (lo << 1) - 1
        buckets.append((lo, hi))
        if hi >= target:
            return buckets
        lo <<= 1


def padded_buckets(counts: Dict[Bucket, int], x_max_rd: int) -> list[Bucket]:
    data_max = max((hi for _lo, hi in counts), default=0)
    target = max(data_max, x_max_rd)
    buckets = log2_buckets_through(target)
    return sorted(set(buckets) | set(counts))


def bucket_label(bucket: Bucket) -> str:
    lo, hi = bucket
    if lo == hi:
        return str(lo)
    return f"{lo}-{hi}"


def parse_histograms(paths: Iterable[Path], pc_offset: str | None) -> Dict[Bucket, int]:
    counts: Dict[Bucket, int] = {}
    for path in paths:
        if path.name.endswith(".pair.hist.log2.txt"):
            continue
        with path.open() as fh:
            header = next(fh, "").strip()
            if header != "pc_offset\tbucket_lo\tbucket_hi\tcount":
                raise ValueError(f"unexpected histogram header in {path}: {header}")
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                pc, lo, hi, count = line.split("\t")
                if pc_offset is not None and pc.lower() != pc_offset.lower():
                    continue
                bucket = (int(lo), int(hi))
                counts[bucket] = counts.get(bucket, 0) + int(count)
    return counts


def plot_histogram(counts: Dict[Bucket, int], output: Path, title: str, x_max_rd: int) -> None:
    total = sum(counts.values())
    if total <= 0:
        raise ValueError("histogram has no samples")

    buckets = padded_buckets(counts, x_max_rd)
    proportions = [counts.get(bucket, 0) / total for bucket in buckets]
    labels = [bucket_label(bucket) for bucket in buckets]
    x = list(range(len(labels)))

    fig_width = max(8.0, min(13.0, 0.35 * len(labels) + 4.0))
    fig, ax = plt.subplots(figsize=(fig_width, 5.0))
    ax.bar(x, proportions, width=0.34, color="#2f6f9f")
    ax.set_title(title)
    ax.set_xlabel("log2 RD bucket")
    ax.set_ylabel("proportion")
    ax.set_xlim(-0.5, len(labels) - 0.5)
    label_step = max(1, len(labels) // 14)
    ax.set_xticks(x[::label_step])
    ax.set_xticklabels(labels[::label_step], rotation=45, ha="right")
    ax.yaxis.set_major_formatter(PercentFormatter(1.0))
    ax.grid(axis="y", alpha=0.25)
    ax.text(
        0.99,
        0.95,
        f"samples={total}",
        transform=ax.transAxes,
        ha="right",
        va="top",
    )
    fig.tight_layout()
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, dpi=160)
    plt.close(fig)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("hist", nargs="+", type=Path, help="*.hist.log2.txt files")
    parser.add_argument("-o", "--output", type=Path, default=Path("rd_hist.png"))
    parser.add_argument("--title", default="Targeted RD log2 histogram")
    parser.add_argument("--pc-offset", help="only plot one pc_offset, e.g. 0x3278")
    parser.add_argument(
        "--x-max-rd",
        type=int,
        default=300000,
        help="pad empty log2 buckets until this RD value is covered (default: 300000)",
    )
    args = parser.parse_args()

    counts = parse_histograms(args.hist, args.pc_offset)
    title = args.title
    if args.pc_offset:
        title += f" ({args.pc_offset})"
    output = resolve_output_path(args.output)
    plot_histogram(counts, output, title, args.x_max_rd)
    print(f"output={output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
