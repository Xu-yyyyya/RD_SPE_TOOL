#!/usr/bin/env python3
"""Join targeted_rd use/reuse pair contexts with external perf call-path cost."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

from rd_format import format_rd_bucket


def normalize_name(name: str) -> str:
    name = name.strip()
    name = re.sub(r"^\[[^\]]+\]\s+", "", name)
    name = re.sub(r"\s+\[[^\]]+\]$", "", name)
    name = re.sub(r"\s+at 0x[0-9a-fA-F]+.*$", "", name)
    return name.strip()


def common_prefix_len(left: List[str], right: List[str]) -> int:
    count = 0
    for a, b in zip(left, right):
        if normalize_name(a) != normalize_name(b):
            break
        count += 1
    return count


def ordered_overlap_count(left: List[str], right: List[str]) -> int:
    pos = 0
    count = 0
    for name in left:
        while pos < len(right) and right[pos] != name:
            pos += 1
        if pos >= len(right):
            break
        count += 1
        pos += 1
    return count


def load_perf(path: Path) -> Tuple[List[Dict[str, Any]], Dict[str, float]]:
    data = json.loads(path.read_text())
    entries = data.get("entries", [])
    function_cost: Dict[str, float] = {}
    for entry in entries:
        percent = max(float(entry.get("children_percent", 0.0)), float(entry.get("self_percent", 0.0)))
        names = [entry.get("symbol", "")]
        names.extend(entry.get("callpath_frames", []))
        for name in names:
            norm = normalize_name(str(name))
            if not norm:
                continue
            function_cost[norm] = max(function_cost.get(norm, 0.0), percent)
    return entries, function_cost


def best_perf_match(functions_leaf_to_root: Iterable[str], perf_entries: List[Dict[str, Any]]) -> Dict[str, Any]:
    funcs = [normalize_name(fn) for fn in functions_leaf_to_root if normalize_name(fn) and normalize_name(fn) != "??"]
    if not funcs:
        return {"percent": 0.0, "confidence": 0.0, "callpath_id": 0, "status": "unmatched", "callpath_text": ""}

    best = {"percent": 0.0, "confidence": 0.0, "callpath_id": 0, "status": "unmatched", "callpath_text": ""}
    for entry in perf_entries:
        frames = [normalize_name(x) for x in entry.get("callpath_frames", []) if normalize_name(x)]
        symbol = normalize_name(str(entry.get("symbol", "")))
        if symbol and (not frames or frames[0] != symbol):
            frames.insert(0, symbol)
        if not frames:
            continue
        if funcs[0] != frames[0]:
            continue

        prefix = common_prefix_len(funcs, frames)
        overlap = ordered_overlap_count(funcs, frames)
        confidence = prefix / len(funcs)

        # OpenMP worker unwind paths may name libgomp internals differently in
        # the target snapshot and in perf.  Treat a non-main OpenMP runtime
        # caller as the worker-thread path when perf resolves start_thread.
        funcs_set = set(funcs)
        frames_set = set(frames)
        pair_has_omp_worker_runtime = any("omp" in fn.lower() for fn in funcs[1:])
        perf_has_worker_entry = bool({"start_thread", "thread_start"} & frames_set)
        perf_has_main_path = "main" in frames_set or "GOMP_parallel" in frames_set
        pair_has_main_path = "main" in funcs_set or "GOMP_parallel" in funcs_set
        if pair_has_omp_worker_runtime and perf_has_worker_entry and not pair_has_main_path:
            confidence = max(confidence, 0.85)
        if pair_has_main_path and perf_has_main_path:
            confidence = max(confidence, 0.85)
        if overlap == len(funcs):
            confidence = max(confidence, 0.75)
        if prefix == 1 and len(funcs) > 1 and confidence < 0.75:
            # Leaf-only matches are intentionally weak; they should not merge
            # distinct call paths such as worker-thread and main-thread OpenMP
            # entries.
            confidence = min(confidence, 0.35)
        if confidence <= 0:
            continue

        percent = max(float(entry.get("children_percent", 0.0)), float(entry.get("self_percent", 0.0)))
        if (confidence, percent) > (best["confidence"], best["percent"]):
            best = {
                "percent": percent,
                "confidence": confidence,
                "callpath_id": int(entry.get("callpath_id", 0)),
                "status": "matched",
                "callpath_text": entry.get("callpath_text", ""),
                "branch_index": int(entry.get("branch_index", 0)),
            }
    return best


def render_frames(
    frames: List[Dict[str, Any]],
    function_cost: Dict[str, float],
    hit_label: str,
    hit_pc_key: str,
) -> List[str]:
    if not frames:
        return ["  (empty callchain)"]
    root_to_leaf = list(reversed(frames))
    lines: List[str] = []
    for depth, frame in enumerate(root_to_leaf):
        fn = normalize_name(str(frame.get("function", ""))) or str(frame.get("text", ""))
        source = str(frame.get("display_source", "") or frame.get("source", ""))
        line = int(frame.get("line", 0) or 0)
        module = str(frame.get("module", ""))
        loc = f"{source}:{line}" if source and line else (f"[{module}]" if module else "")
        percent = function_cost.get(fn, 0.0)
        prefix = "" if depth == 0 else "    " * (depth - 1) + "`-- "
        suffix = f"  [{hit_label} {hit_pc_key}]" if depth == len(root_to_leaf) - 1 else ""
        cost = f"  [perf cost {percent:.2f}%]" if percent > 0 else ""
        loc_text = f" ({loc})" if loc else ""
        lines.append(f"{prefix}{fn}{loc_text}{cost}{suffix}")
    return lines


def bucket_rows(entry: Dict[str, Any]) -> List[Tuple[int, int, int, float]]:
    total = int(entry.get("total_count", 0))
    rows = []
    for bucket in entry.get("buckets", []):
        count = int(bucket.get("count", 0))
        ratio = count / total if total else 0.0
        rows.append((int(bucket["bucket_lo"]), int(bucket["bucket_hi"]), count, ratio))
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pair-report-json", required=True, type=Path)
    parser.add_argument("--perf-callpaths", required=True, type=Path)
    parser.add_argument("--output-prefix", required=True, type=Path)
    parser.add_argument("--top", type=int, default=50)
    args = parser.parse_args()

    pair_data = json.loads(args.pair_report_json.read_text())
    perf_entries, function_cost = load_perf(args.perf_callpaths)
    candidates: List[Dict[str, Any]] = []
    for entry in pair_data.get("entries", []):
        seed_match = best_perf_match(entry.get("seed_functions_leaf_to_root", []), perf_entries)
        reuse_match = best_perf_match(entry.get("reuse_functions_leaf_to_root", []), perf_entries)
        chosen = seed_match if seed_match["percent"] >= reuse_match["percent"] else reuse_match
        perf_percent = float(chosen.get("percent", 0.0))
        enriched = dict(entry)
        enriched.update(
            {
                "perf_cost_percent": perf_percent,
                "matched_callpath_id": int(chosen.get("callpath_id", 0)),
                "matched_callpath_text": chosen.get("callpath_text", ""),
                "seed_perf_cost_percent": float(seed_match.get("percent", 0.0)),
                "seed_matched_callpath_id": int(seed_match.get("callpath_id", 0)),
                "seed_matched_callpath_text": seed_match.get("callpath_text", ""),
                "reuse_perf_cost_percent": float(reuse_match.get("percent", 0.0)),
                "reuse_matched_callpath_id": int(reuse_match.get("callpath_id", 0)),
                "reuse_matched_callpath_text": reuse_match.get("callpath_text", ""),
            }
        )
        candidates.append(enriched)

    candidates.sort(
        key=lambda item: (
            item["perf_cost_percent"],
            int(item.get("total_count", 0)),
        ),
        reverse=True,
    )

    report_path = Path(str(args.output_prefix) + "_optimization_report.md")
    tsv_path = Path(str(args.output_prefix) + "_optimization.tsv")
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with tsv_path.open("w") as out:
        out.write(
            "rank\tentry_id\tperf_cost_percent\tmatched_callpath_id\t"
            "seed_matched_callpath_id\treuse_matched_callpath_id\t"
            "total_count\tseed_pc_offset\treuse_pc\n"
        )
        for rank, entry in enumerate(candidates, 1):
            out.write(
                f"{rank}\t{entry['entry_id']}\t{entry['perf_cost_percent']:.6f}\t"
                f"{entry['matched_callpath_id']}\t{entry['seed_matched_callpath_id']}\t"
                f"{entry['reuse_matched_callpath_id']}\t{entry['total_count']}\t"
                f"{entry['seed_pc_offset']}\t{entry['reuse_pc']}\n"
            )

    with report_path.open("w") as out:
        out.write("# Use-Reuse Pair Optimization Candidates\n\n")
        out.write(f"- pair_report_json: `{args.pair_report_json}`\n")
        out.write(f"- perf_callpaths: `{args.perf_callpaths}`\n")
        out.write(f"- candidates: `{len(candidates)}`\n\n")
        for rank, entry in enumerate(candidates[: args.top], 1):
            out.write(f"## Candidate {rank}\n\n")
            out.write(f"- entry_id: `{entry['entry_id']}`\n")
            out.write(f"- perf_cost_percent: `{entry['perf_cost_percent']:.6f}`\n")
            out.write(f"- total_count: `{entry['total_count']}`\n\n")
            out.write(
                "Use-side context "
                f"(perf_callpath_id={entry['seed_matched_callpath_id']}, "
                f"cost={entry['seed_perf_cost_percent']:.6f}%):\n\n"
            )
            if entry.get("seed_matched_callpath_text"):
                out.write(f"- matched_perf_callpath: `{entry['seed_matched_callpath_text']}`\n\n")
            out.write("```text\n")
            for line in render_frames(
                entry.get("seed_frames", []),
                {},
                "USE HIT",
                str(entry.get("seed_pc_offset", "")),
            ):
                out.write(line + "\n")
            out.write("```\n\n")
            out.write(
                "Reuse-side context "
                f"(perf_callpath_id={entry['reuse_matched_callpath_id']}, "
                f"cost={entry['reuse_perf_cost_percent']:.6f}%):\n\n"
            )
            if entry.get("reuse_matched_callpath_text"):
                out.write(f"- matched_perf_callpath: `{entry['reuse_matched_callpath_text']}`\n\n")
            out.write("```text\n")
            for line in render_frames(
                entry.get("reuse_frames", []),
                {},
                "REUSE HIT",
                str(entry.get("reuse_pc", "")),
            ):
                out.write(line + "\n")
            out.write("```\n\n")
            out.write("RD buckets:\n\n")
            out.write("| bucket | count | ratio |\n")
            out.write("| --- | ---: | ---: |\n")
            for lo, hi, count, ratio in bucket_rows(entry):
                out.write(f"| {format_rd_bucket((lo, hi))} | {count} | {ratio:.6f} |\n")
            out.write("\n")

    print(f"wrote {report_path}")
    print(f"wrote {tsv_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
