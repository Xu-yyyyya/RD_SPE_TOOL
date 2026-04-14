#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Reuse-time and Featherlight stack-distance analysis.

Input format:
- Reads legacy binary ``.sample0`` files with fixed-size records
  of 16 bytes: ``addr`` (u64) followed by ``time`` (u64), little-endian.
- Rejects newer ARM SPE ``.sample0`` files that carry ``addr,time,pc``
  records, because this script is only for the deprecated reuse-distance flow.
- For multithread runs, pass a prefix or any one thread file and the
  tool will collect ``name.t*.sample0`` and merge streams by timestamp.

Outputs:
- temporal_reuse_time_hist.png: Histogram of temporal reuse time Δt
- featherlight_time_hist.png : Histogram of Featherlight-estimated RD (RD ≈ F(Δt))

Examples:
  # single thread file
  python3 postproc/reuse_distance.py /home/xya/nmo/exchange2_new.t123.sample0 \
      --out-dir /home/xya/nmo/postproc/out --no-show
  # prefix: automatically merges /home/xya/nmo/exchange2_new.t*.sample0
  python3 postproc/reuse_distance.py /home/xya/nmo/exchange2_new \
      --out-dir /home/xya/nmo/postproc/out --no-show
"""

from __future__ import annotations
import os
import struct
import random
import bisect
import re
import glob
import heapq
from typing import Iterable, Iterator, List, Tuple, Dict, Optional
from collections import defaultdict

import matplotlib.pyplot as plt

# (addr, time)
Record = Tuple[int, int]

# legacy little-endian, two u64 (addr, time)
_RECORD_STRUCT = struct.Struct('<QQ')


def _infer_info_path(sample_path: str) -> Optional[str]:
    d = os.path.dirname(sample_path) or '.'
    b = os.path.basename(sample_path)
    for pat in (r'(.+?)\.t\d+\.sample\d+$', r'(.+?)\.sample\d+$'):
        m = re.match(pat, b)
        if m:
            return os.path.join(d, f'{m.group(1)}.info')
    return None


def _sample0_error(path: str, detail: str) -> ValueError:
    return ValueError(f"Unsupported .sample0 format for {path}: {detail}")


def _detect_sample0_layout(path: str) -> int:
    info_path = _infer_info_path(path)
    record_bytes = None
    record_fields = None
    sample_pc_present = None

    if info_path and os.path.exists(info_path):
        with open(info_path, 'r', encoding='utf-8', errors='replace') as f:
            for raw_line in f:
                line = raw_line.strip()
                if line.startswith('sample_record_bytes='):
                    record_bytes = int(line.split('=', 1)[1])
                elif line.startswith('sample_record_fields='):
                    record_fields = line.split('=', 1)[1]
                elif line.startswith('sample_pc_present='):
                    sample_pc_present = line.split('=', 1)[1] == '1'

        if sample_pc_present or record_bytes == 24 or (record_fields and 'pc' in record_fields.split(',')):
            raise _sample0_error(
                path,
                "24-byte ARM SPE addr,time,pc records are no longer valid input for reuse-distance analysis.",
            )
        if record_bytes is not None and record_bytes != _RECORD_STRUCT.size:
            raise _sample0_error(path, f"expected 16-byte legacy records, found {record_bytes}-byte records.")
        if record_fields and record_fields != 'addr,time':
            raise _sample0_error(path, f"expected addr,time fields, found {record_fields}.")

        return _RECORD_STRUCT.size

    size = os.path.getsize(path)
    if size == 0:
        return _RECORD_STRUCT.size
    if size % 24 == 0 and size % _RECORD_STRUCT.size != 0:
        raise _sample0_error(
            path,
            "24-byte ARM SPE addr,time,pc records are no longer valid input for reuse-distance analysis.",
        )
    if size % _RECORD_STRUCT.size == 0 and size % 24 != 0:
        return _RECORD_STRUCT.size
    if size % _RECORD_STRUCT.size == 0 and size % 24 == 0:
        raise _sample0_error(
            path,
            "record size is ambiguous between 16-byte legacy and 24-byte addr,time,pc layouts; keep the matching .info file with the samples.",
        )
    raise _sample0_error(path, f"file size {size} is not a whole number of 16-byte legacy records.")


def read_sample0(path: str) -> Iterator[Record]:
    """Stream ``(addr, time)`` records from a ``.sample0`` binary file.

    Raises ValueError if trailing record is truncated.
    """
    record_size = _detect_sample0_layout(path)
    with open(path, 'rb') as f:
        while True:
            chunk = f.read(record_size)
            if not chunk:
                return
            if len(chunk) != record_size:
                raise ValueError(f"Truncated record: expected {record_size} bytes")
            addr, ts = _RECORD_STRUCT.unpack(chunk)
            yield addr, ts


def expand_sample_paths(arg: str) -> List[str]:
    """Expand a user-provided path/prefix into a list of name.t*.sample0 files.

    Rules:
      - If arg is a directory: return sorted(dir/*.t*.sample0). If none, fallback to dir/*.sample0.
      - If arg endswith .sample0 and matches name.t<tid>.sample0: glob siblings name.t*.sample0.
      - If arg endswith .sample0 but not t<tid>: return [arg].
      - Otherwise, treat as prefix 'name' and glob name.t*.sample0 (in its directory).
    """
    if os.path.isdir(arg):
        cand = sorted(glob.glob(os.path.join(arg, '*.t*.sample0')))
        if cand:
            return cand
        return sorted(glob.glob(os.path.join(arg, '*.sample0')))

    if arg.endswith('.sample0'):
        d = os.path.dirname(arg) or '.'
        b = os.path.basename(arg)
        m = re.match(r'(.+?)\.t\d+\.sample0$', b)
        if m:
            prefix = m.group(1)
            files = sorted(glob.glob(os.path.join(d, f'{prefix}.t*.sample0')))
            return files if files else [arg]
        else:
            return [arg]

    # treat as prefix
    d = os.path.dirname(arg) or '.'
    name = os.path.basename(arg)
    files = sorted(glob.glob(os.path.join(d, f'{name}.t*.sample0')))
    return files if files else [arg]


def merge_sample_streams(paths: List[str], limit: Optional[int] = None) -> Iterator[Record]:
    """K-way merge of per-thread streams by timestamp ascending.

    Assumes each file stores records as (addr, time). If files are unsorted by time,
    merge remains correct but may interleave suboptimally.
    """
    iters: List[Iterator[Record]] = [read_sample0(p) for p in paths]
    heap: List[Tuple[int, int, int]] = []  # (time, idx, addr)
    for idx, it in enumerate(iters):
        try:
            a, t = next(it)
            heap.append((t, idx, a))
        except StopIteration:
            pass
    heapq.heapify(heap)
    produced = 0
    while heap:
        if limit is not None and produced >= limit:
            return
        t, idx, a = heapq.heappop(heap)
        yield (a, t)
        produced += 1
        try:
            a2, t2 = next(iters[idx])
            heapq.heappush(heap, (t2, idx, a2))
        except StopIteration:
            pass


def temporal_reuse_time(addrs: Iterable[int], times: Iterable[int]) -> List[Optional[int]]:
    """Compute temporal reuse time Δt for each access.

    For address a at time t, if previously seen at time t_prev, Δt = t - t_prev.
    First occurrence yields None.
    """
    last_time: Dict[int, int] = {}
    res: List[Optional[int]] = []
    for a, t in zip(addrs, times):
        if a in last_time:
            dt = t - last_time[a]
            res.append(int(dt) if dt >= 0 else None)
        else:
            res.append(None)
        last_time[a] = t
    return res


def plot_hist(distances: Iterable[Optional[int]], title: str, bins: int = 50, xmax: Optional[int] = None, out_path: Optional[str] = None, xlabel: str = 'Value') -> None:
    """Plot a histogram for distances."""
    vals = [d for d in distances if d is not None and d >= 0]
    if not vals:
        print(f"No data to plot for {title}")
        return
    if xmax is not None:
        vals = [v for v in vals if v <= xmax]
    plt.figure(figsize=(8, 4))
    plt.hist(vals, bins=bins, log=True)
    plt.xlabel(xlabel)
    plt.ylabel('Frequency (log scale)')
    plt.title(title)
    plt.tight_layout()
    if out_path:
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        plt.savefig(out_path)
        print(f"Saved: {out_path}")


def _logspace_int(lo: int, hi: int, k: int) -> List[int]:
    lo = max(1, lo)
    hi = max(lo, hi)
    if k <= 1:
        return [hi]
    xs = []
    for i in range(k):
        t = i / (k - 1)
        val = int(round(lo * (hi / lo) ** t))
        xs.append(max(1, val))
    xs = sorted(set(xs))
    return xs


def estimate_footprint_time(addrs: List[int], times: List[int], durations: List[int], samples_per_tau: int = 256, seed: int = 42) -> Dict[int, float]:
    """Estimate footprint F(T) with a sliding window per duration.

    For each duration T, maintain a [s,e) window with times[e-1]-times[s] <= T,
    update a frequency table to track distinct addresses, and sample windows by
    advancing s with a fixed stride derived from samples_per_tau.
    """
    n = len(addrs)
    if n == 0:
        return {d: 0.0 for d in durations}
    # Ensure unique, sorted durations for stable interpolation behavior upstream
    durs = sorted(set(d for d in durations if d > 0))
    if not durs:
        return {d: 0.0 for d in durations}
    stride = max(1, n // max(1, samples_per_tau))
    result: Dict[int, float] = {}
    for dur in durs:
        s = 0
        e = 0
        freq: Dict[int, int] = defaultdict(int)
        distinct = 0
        sum_distinct = 0.0
        num_windows = 0
        while s < n:
            # expand e while within duration
            while e < n and times[e] - times[s] <= dur:
                a = addrs[e]
                if freq[a] == 0:
                    distinct += 1
                freq[a] += 1
                e += 1
            sum_distinct += distinct
            num_windows += 1
            # advance start by stride, removing elements
            step = stride
            rem = min(step, e - s)
            for j in range(rem):
                a = addrs[s + j]
                cnt = freq[a] - 1
                if cnt == 0:
                    distinct -= 1
                    del freq[a]
                else:
                    freq[a] = cnt
            s += step
            if s >= e:
                # window becomes empty
                freq.clear()
                distinct = 0
                e = s
        result[dur] = (sum_distinct / num_windows) if num_windows > 0 else 0.0
    # Fill for original durations (including non-positive)
    out: Dict[int, float] = {}
    for d in durations:
        out[d] = result.get(d, 0.0)
    return out


def _interp_footprint(keys: List[int], values: List[float], x: int) -> float:
    """Piecewise-linear interpolate value at x over monotonic integer keys."""
    if not keys:
        return 0.0
    if x <= keys[0]:
        return values[0]
    if x >= keys[-1]:
        return values[-1]
    i = bisect.bisect_left(keys, x)
    if keys[i] == x:
        return values[i]
    x0, x1 = keys[i - 1], keys[i]
    y0, y1 = values[i - 1], values[i]
    t = (x - x0) / float(x1 - x0)
    return y0 + t * (y1 - y0)


def featherlight_rd_from_time(addrs: List[int], times: List[int], durations: List[int], F: Dict[int, float]) -> List[Optional[int]]:
    """Map time-based reuse-time Δt to RD via RD ≈ F(Δt)."""
    rd: List[Optional[int]] = []
    F_keys = sorted(F.keys())
    F_vals = [F[k] for k in F_keys]
    last_time: Dict[int, int] = {}
    for a, t in zip(addrs, times):
        if a in last_time:
            dt = max(1, int(t - last_time[a]))
            est = _interp_footprint(F_keys, F_vals, dt)
            rd.append(int(round(est)))
        else:
            rd.append(None)
        last_time[a] = t
    return rd


def main(path: str, limit: Optional[int] = None, mask: Optional[int] = None, out_dir: Optional[str] = None, no_show: bool = False,
         taus: Optional[List[int]] = None, samples: int = 256) -> None:
    """CLI: compute temporal reuse time and Featherlight RD, plot PNGs."""
    # Expand to multi-thread inputs and merge by time
    paths = expand_sample_paths(path)
    if len(paths) > 1:
        print(f"Merging {len(paths)} sample files by time ...")
        recs = merge_sample_streams(paths, limit)
    else:
        recs = read_sample0(paths[0])
        if limit is not None:
            recs = (r for i, r in enumerate(recs) if i < limit)

    addrs: List[int] = []
    times: List[int] = []
    for addr, ts in recs:
        if mask is not None:
            addr &= mask
        addrs.append(addr)
        times.append(ts)

    print(f"Total accesses: {len(addrs)}")
    print(f"Unique addresses: {len(set(addrs))}")

    # Temporal reuse time (Δt)
    rt = temporal_reuse_time(addrs, times)
    rt_path = os.path.join(out_dir, 'temporal_reuse_time_hist.png') if out_dir else None
    plot_hist(rt, 'Temporal reuse time Δt', out_path=rt_path, xlabel='Δt (time units)')

    # Featherlight (time-window mapping): RD ≈ F(Δt)
    if times:
        tspan = max(1, times[-1] - times[0])
        auto_durs = _logspace_int(1, max(1, tspan // 4), 32)
        sel_durs = taus if taus else auto_durs
        F = estimate_footprint_time(addrs, times, sel_durs, samples_per_tau=samples)
        rd_est = featherlight_rd_from_time(addrs, times, sel_durs, F)
        fl_path = os.path.join(out_dir, 'featherlight_time_hist.png') if out_dir else None
        plot_hist(rd_est, 'Featherlight RD (time-window mapping)', out_path=fl_path, xlabel='RD ≈ F(Δt)')

    if not no_show:
        plt.show()


if __name__ == '__main__':
    import argparse
    p = argparse.ArgumentParser(description='Compute temporal reuse time and Featherlight RD from .sample0 records')
    p.add_argument('path', help='Path/prefix/dir to .sample0 files or name.t*.sample0')
    p.add_argument('--limit', type=int, help='Limit number of merged records for quick run')
    p.add_argument('--mask', type=lambda s: int(s, 0), help='Apply bitmask to addresses, e.g., 0xFFFFFFFFFFFFF000 for page')
    p.add_argument('--out-dir', help='Directory to save histogram PNGs')
    p.add_argument('--no-show', action='store_true', help='Do not open interactive windows (headless)')
    p.add_argument('--taus', help='Comma-separated durations (time window sizes)')
    p.add_argument('--samples', type=int, default=256, help='Samples per tau for footprint estimation')
    args = p.parse_args()
    taus = None
    if args.taus:
        try:
            taus = [int(x.strip(), 0) for x in args.taus.split(',') if x.strip()]
        except Exception:
            raise SystemExit('Invalid --taus; provide comma-separated integers (allow 0x prefix)')
    main(args.path, args.limit, args.mask, args.out_dir, args.no_show, taus, args.samples)
