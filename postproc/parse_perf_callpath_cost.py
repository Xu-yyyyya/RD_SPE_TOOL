#!/usr/bin/env python3
"""Parse `perf report --stdio` call-path cost into JSON/TSV.

The parser intentionally targets the stable stdio report shape used by this
project:

    perf report --stdio --no-children --percent-limit 0

It keeps enough information for offline matching with targeted_rd use/reuse
pair contexts: percent, DSO, leaf symbol, and a normalized call-path frame list.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional


BRANCH_RE = re.compile(r"(?:^|\|)\s*--(?P<percent>\d+(?:\.\d+)?)%--(?P<frame>.+)$")


def normalize_symbol(symbol: str) -> str:
    symbol = symbol.strip()
    symbol = re.sub(r"^\[[^\]]+\]\s+", "", symbol)
    symbol = re.sub(r"\s+\+0x[0-9a-fA-F]+$", "", symbol)
    return symbol.strip()


def clean_callgraph_frame(line: str) -> Optional[str]:
    text = line.strip()
    if not text or text == "|":
        return None
    text = text.replace("|", "").strip()
    text = re.sub(r"^-+", "", text).strip()
    text = re.sub(r"^--\d+(?:\.\d+)?%--", "", text).strip()
    text = re.sub(r"^\d+(?:\.\d+)?%--", "", text).strip()
    return normalize_symbol(text) if text else None


def parse_entry_line(line: str) -> Optional[Dict[str, Any]]:
    stripped = line.strip()
    if not re.match(r"^\d+(?:\.\d+)?%", stripped):
        return None

    parts = re.split(r"\s{2,}", stripped)
    if len(parts) < 4:
        return None

    first_percent = float(parts[0].rstrip("%"))
    index = 1
    if index < len(parts) and re.match(r"^\d+(?:\.\d+)?%$", parts[index]):
        children_percent = first_percent
        self_percent = float(parts[index].rstrip("%"))
        index += 1
    else:
        self_percent = first_percent
        children_percent = first_percent

    if len(parts) <= index + 2:
        return None

    command = parts[index]
    dso = parts[index + 1]
    symbol = normalize_symbol(parts[index + 2])
    return {
        "self_percent": self_percent,
        "children_percent": children_percent,
        "command": command,
        "module": dso,
        "symbol": symbol,
        "callpath_frames": [symbol] if symbol else [],
        "callpath_text": symbol,
    }


def dedupe_consecutive(frames: List[str]) -> List[str]:
    out: List[str] = []
    for frame in frames:
        if frame and (not out or out[-1] != frame):
            out.append(frame)
    return out


def finalize_entry(entry: Dict[str, Any], graph_lines: List[str]) -> List[Dict[str, Any]]:
    symbol = normalize_symbol(str(entry.get("symbol", "")))
    fallback_frames: List[str] = [symbol] if symbol else []
    branches: List[Dict[str, Any]] = []
    current_branch: Optional[Dict[str, Any]] = None

    for raw in graph_lines:
        stripped = raw.strip()
        if not stripped or stripped == "|":
            continue

        branch_match = BRANCH_RE.search(stripped)
        if branch_match:
            frame = normalize_symbol(branch_match.group("frame"))
            current_branch = {
                "branch_percent": float(branch_match.group("percent")),
                "frames": dedupe_consecutive([symbol, frame] if symbol else [frame]),
            }
            branches.append(current_branch)
            continue

        frame = clean_callgraph_frame(raw)
        if not frame or frame in ("-", "."):
            continue
        if frame == symbol and not branches:
            continue
        if current_branch is not None:
            current_branch["frames"] = dedupe_consecutive(current_branch["frames"] + [frame])
        else:
            fallback_frames.append(frame)

    out: List[Dict[str, Any]] = []
    if branches:
        for branch_index, branch in enumerate(branches, 1):
            branch_entry = dict(entry)
            percent = float(branch["branch_percent"])
            branch_entry["self_percent"] = percent
            branch_entry["children_percent"] = percent
            branch_entry["parent_symbol_percent"] = float(entry.get("self_percent", percent))
            branch_entry["branch_index"] = branch_index
            branch_entry["branch_percent"] = percent
            branch_entry["callpath_frames"] = dedupe_consecutive(branch["frames"])
            branch_entry["callpath_text"] = " <- ".join(branch_entry["callpath_frames"])
            out.append(branch_entry)
        return out

    fallback_entry = dict(entry)
    fallback_entry["branch_index"] = 0
    fallback_entry["branch_percent"] = float(entry.get("self_percent", 0.0))
    fallback_entry["callpath_frames"] = dedupe_consecutive(fallback_frames)
    fallback_entry["callpath_text"] = " <- ".join(fallback_entry["callpath_frames"])
    return [fallback_entry]


def parse_report(path: Path) -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []
    current: Optional[Dict[str, Any]] = None
    graph_lines: List[str] = []

    for raw in path.read_text(errors="replace").splitlines():
        parsed = parse_entry_line(raw)
        if parsed is not None:
            if current is not None:
                entries.extend(finalize_entry(current, graph_lines))
            current = parsed
            graph_lines = []
            continue

        if current is None:
            continue

        stripped = raw.strip()
        if not stripped:
            continue
        if stripped.startswith("#"):
            continue
        if raw.startswith(" ") or raw.startswith("\t"):
            graph_lines.append(raw)

    if current is not None:
        entries.extend(finalize_entry(current, graph_lines))

    for idx, entry in enumerate(entries, 1):
        entry["callpath_id"] = idx
        entry["frame_depth"] = len(entry.get("callpath_frames", []))
    return entries


def write_tsv(path: Path, entries: List[Dict[str, Any]]) -> None:
    with path.open("w") as out:
        out.write(
            "callpath_id\tself_percent\tchildren_percent\tcommand\tmodule\tsymbol\t"
            "frame_depth\tcallpath_text\n"
        )
        for entry in entries:
            out.write(
                f"{entry['callpath_id']}\t"
                f"{entry['self_percent']:.6f}\t"
                f"{entry['children_percent']:.6f}\t"
                f"{entry.get('command', '')}\t"
                f"{entry.get('module', '')}\t"
                f"{entry.get('symbol', '')}\t"
                f"{entry.get('frame_depth', 0)}\t"
                f"{entry.get('callpath_text', '')}\n"
            )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--output-prefix", required=True, type=Path)
    args = parser.parse_args()

    entries = parse_report(args.report)
    json_path = Path(str(args.output_prefix) + ".callpaths.json")
    tsv_path = Path(str(args.output_prefix) + ".callpaths.tsv")
    json_path.parent.mkdir(parents=True, exist_ok=True)
    with json_path.open("w") as out:
        json.dump({"report": str(args.report), "entries": entries}, out, indent=2)
    write_tsv(tsv_path, entries)

    print(f"wrote {json_path}")
    print(f"wrote {tsv_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
