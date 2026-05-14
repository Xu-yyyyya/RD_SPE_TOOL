#!/usr/bin/env python3
"""Plot expected Rdbench histogram and observed targeted-RD histogram together."""

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


def padded_buckets(expected: Dict[Bucket, int], observed: Dict[Bucket, int], x_max_rd: int) -> list[Bucket]:
    data_max = max((hi for _lo, hi in set(expected) | set(observed)), default=0)
    target = max(data_max, x_max_rd)
    buckets = log2_buckets_through(target)
    return sorted(set(buckets) | set(expected) | set(observed))


def bucket_label(bucket: Bucket) -> str:
    lo, hi = bucket
    if lo == hi:
        return str(lo)
    return f"{lo}-{hi}"


def parse_global_expected(manifest: Path) -> Dict[Bucket, int]:
    counts: Dict[Bucket, int] = {}
    with manifest.open() as fh:
        for line in fh:
            line = line.strip()
            if not line.startswith("micro_expected_exact_count="):
                continue
            _key, payload = line.split("=", 1)
            _bucket, lo, hi, count = payload.split("\t")
            bucket = (int(lo), int(hi))
            counts[bucket] = counts.get(bucket, 0) + int(count)
    if not counts:
        raise ValueError(f"no micro_expected_exact_count entries in {manifest}")
    return counts


def parse_hotspot_expected(manifest: Path, hotspot: int) -> Dict[Bucket, int]:
    counts: Dict[Bucket, int] = {}
    prefix = f"micro_hotspot_expected_exact_count={hotspot}\t"
    with manifest.open() as fh:
        for line in fh:
            line = line.strip()
            if not line.startswith(prefix):
                continue
            _key, payload = line.split("=", 1)
            _hotspot, _bucket, lo, hi, count = payload.split("\t")
            bucket = (int(lo), int(hi))
            counts[bucket] = counts.get(bucket, 0) + int(count)
    if not counts:
        raise ValueError(f"no expected entries for hotspot {hotspot} in {manifest}")
    return counts


def parse_hotspot_pc_offset(manifest: Path, hotspot: int) -> str:
    prefix = f"micro_hotspot_seed_pc_offset={hotspot}\t"
    with manifest.open() as fh:
        for line in fh:
            line = line.strip()
            if line.startswith(prefix):
                return line.split("\t", 1)[1]
    raise ValueError(f"no seed pc offset for hotspot {hotspot} in {manifest}")


def parse_observed(paths: Iterable[Path], pc_offset: str | None) -> Dict[Bucket, int]:
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


def normalized(counts: Dict[Bucket, int], buckets: list[Bucket]) -> list[float]:
    total = sum(counts.values())
    if total <= 0:
        return [0.0 for _ in buckets]
    return [counts.get(bucket, 0) / total for bucket in buckets]


def similarity_s(expected: Dict[Bucket, int], observed: Dict[Bucket, int]) -> float:
    expected_total = sum(expected.values())
    observed_total = sum(observed.values())
    if expected_total <= 0 or observed_total <= 0:
        return 0.0
    buckets = set(expected) | set(observed)
    l1 = sum(
        abs(expected.get(bucket, 0) / expected_total - observed.get(bucket, 0) / observed_total)
        for bucket in buckets
    )
    return max(0.0, 1.0 - l1 / 2.0)


def plot_comparison(
    expected: Dict[Bucket, int],
    observed: Dict[Bucket, int],
    output: Path,
    title: str,
    x_max_rd: int,
) -> None:
    buckets = padded_buckets(expected, observed, x_max_rd)
    if not buckets:
        raise ValueError("no buckets to plot")

    labels = [bucket_label(bucket) for bucket in buckets]
    x = list(range(len(buckets)))
    expected_props = normalized(expected, buckets)
    observed_props = normalized(observed, buckets)
    score = similarity_s(expected, observed)

    fig_width = max(9.0, min(13.5, 0.38 * len(labels) + 5.0))
    fig, ax = plt.subplots(figsize=(fig_width, 5.5))
    width = 0.26
    ax.bar([value - width / 2 for value in x], expected_props, width, label="expected", color="#4f8f43")
    ax.bar([value + width / 2 for value in x], observed_props, width, label="observed", color="#bf6f2f")
    ax.set_title(title)
    ax.set_xlabel("log2 RD bucket")
    ax.set_ylabel("proportion")
    ax.set_xlim(-0.5, len(labels) - 0.5)
    label_step = max(1, len(labels) // 14)
    ax.set_xticks(x[::label_step])
    ax.set_xticklabels(labels[::label_step], rotation=45, ha="right")
    ax.yaxis.set_major_formatter(PercentFormatter(1.0))
    ax.grid(axis="y", alpha=0.25)
    ax.legend()
    ax.text(
        0.99,
        0.95,
        f"S={score:.6f}\nexpected={sum(expected.values())}\nobserved={sum(observed.values())}",
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
    parser.add_argument("--manifest", required=True, type=Path, help="Rdbench .hotpc manifest")
    parser.add_argument("--hist", required=True, nargs="+", type=Path, help="observed *.hist.log2.txt files")
    parser.add_argument("-o", "--output", type=Path, default=Path("rd_acc_compare.png"))
    parser.add_argument("--title", default="Expected vs observed RD histogram")
    parser.add_argument("--hotspot", type=int, help="compare one hotspot by manifest hotspot id")
    parser.add_argument("--pc-offset", help="compare one observed pc_offset, e.g. 0x3278")
    parser.add_argument(
        "--x-max-rd",
        type=int,
        default=300000,
        help="pad empty log2 buckets until this RD value is covered (default: 300000)",
    )
    args = parser.parse_args()

    pc_offset = args.pc_offset
    if args.hotspot is not None:
        expected = parse_hotspot_expected(args.manifest, args.hotspot)
        inferred_pc = parse_hotspot_pc_offset(args.manifest, args.hotspot)
        if pc_offset is not None and pc_offset.lower() != inferred_pc.lower():
            raise ValueError(f"--pc-offset {pc_offset} does not match hotspot {args.hotspot} pc {inferred_pc}")
        pc_offset = inferred_pc
        title = f"{args.title} (hotspot {args.hotspot}, {pc_offset})"
    else:
        expected = parse_global_expected(args.manifest)
        title = args.title
        if pc_offset:
            title += f" ({pc_offset})"

    observed = parse_observed(args.hist, pc_offset)
    output = resolve_output_path(args.output)
    plot_comparison(expected, observed, output, title, args.x_max_rd)
    print(f"output={output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
