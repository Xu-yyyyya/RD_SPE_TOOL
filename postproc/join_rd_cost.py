#!/usr/bin/env python3
"""Join targeted RD pair histograms with cpu-clock callpath cost summaries."""

from __future__ import annotations

import argparse
import subprocess
from collections import defaultdict
from pathlib import Path
from typing import Dict, Iterable, Tuple


def parse_info(path: Path) -> Dict[str, str]:
    out: Dict[str, str] = {}
    with path.open() as fh:
        for line in fh:
            line = line.strip()
            if line and "=" in line:
                key, value = line.split("=", 1)
                out[key] = value
    return out


def symbolize_function(binary: Path, pc_offset: int) -> str:
    proc = subprocess.run(
        ["addr2line", "-f", "-C", "-e", str(binary), f"0x{pc_offset:x}"],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if proc.returncode != 0:
        return f"0x{pc_offset:x}"
    lines = proc.stdout.splitlines()
    if not lines:
        return f"0x{pc_offset:x}"
    return lines[0].strip() or f"0x{pc_offset:x}"


def parse_cost_functions(path: Path) -> Dict[str, float]:
    inclusive = defaultdict(float)
    with path.open() as fh:
        header = next(fh, "")
        for line in fh:
            parts = line.rstrip("\n").split("\t", 2)
            if len(parts) != 3:
                continue
            try:
                fraction = float(parts[1])
            except ValueError:
                continue
            frames = [frame.strip() for frame in parts[2].split("<-")]
            seen = set()
            for frame in frames:
                fn = frame.split("@", 1)[0].strip()
                if not fn or fn in seen:
                    continue
                inclusive[fn] += fraction
                seen.add(fn)
    return dict(inclusive)


def parse_pair_hist(paths: Iterable[Path], long_rd_min: int) -> Dict[int, int]:
    long_counts = defaultdict(int)
    for path in paths:
        with path.open() as fh:
            header = next(fh, "")
            for line in fh:
                parts = line.strip().split("\t")
                if len(parts) < 7:
                    continue
                try:
                    seed_pc = int(parts[0], 16)
                    bucket_lo = int(parts[4], 10)
                    count = int(parts[6], 10)
                except ValueError:
                    continue
                if bucket_lo >= long_rd_min:
                    long_counts[seed_pc] += count
    return dict(long_counts)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--info", required=True, type=Path)
    parser.add_argument("--pair-hist", required=True, nargs="+", type=Path)
    parser.add_argument("--cost-callpaths", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--long-rd-min", type=int, default=1024)
    args = parser.parse_args()

    info = parse_info(args.info)
    binary = Path(info.get("main_binary", ""))
    if not binary.exists():
        raise SystemExit(f"main_binary not found: {binary}")

    cost_by_function = parse_cost_functions(args.cost_callpaths)
    long_by_pc = parse_pair_hist(args.pair_hist, args.long_rd_min)

    rows = []
    for pc_offset, long_count in long_by_pc.items():
        function = symbolize_function(binary, pc_offset)
        cost_share = cost_by_function.get(function)
        priority = long_count * (cost_share if cost_share is not None else 0.0)
        rows.append((priority, long_count, cost_share, pc_offset, function))
    rows.sort(reverse=True)

    with args.output.open("w") as out:
        out.write("# RD / Callpath Cost Optimization Candidates\n\n")
        out.write(f"- binary: `{binary}`\n")
        out.write(f"- long_rd_min: {args.long_rd_min}\n")
        out.write("- join_policy: seed function vs inclusive cpu-clock function cost\n\n")
        out.write("| rank | seed_pc_offset | function | long_rd_count | cpu_time_share | priority |\n")
        out.write("|---:|---:|---|---:|---:|---:|\n")
        for rank, (priority, long_count, cost_share, pc_offset, function) in enumerate(rows, start=1):
            cost_text = "unknown" if cost_share is None else f"{cost_share:.6f}"
            out.write(
                f"| {rank} | 0x{pc_offset:x} | `{function}` | {long_count} | "
                f"{cost_text} | {priority:.6f} |\n"
            )
    print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
