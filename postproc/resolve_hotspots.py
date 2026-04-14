#!/usr/bin/env python3
"""Resolve ARM SPE hotspot manifests to symbols, source lines, and instructions.

Input:
- ``.hotpc`` files emitted by the runtime hotspot aggregator.

Resolution strategy:
1. Parse unique ``(module path, pc_offset)`` hotspot locations.
2. Use ``addr2line`` to resolve function and source line.
3. If line info is missing, fall back to ``nm`` and ``objdump``.
4. Emit a readable text report to stdout or a file.

Examples:
  python3 postproc/resolve_hotspots.py /home/xya/SPE_tool/build/spe_hotspot_mainonly.hotpc
  python3 postproc/resolve_hotspots.py /home/xya/SPE_tool/build/spe_hotspot_mainonly.hotpc \
      --output /home/xya/SPE_tool/build/spe_hotspot_mainonly.resolved.txt
"""

from __future__ import annotations

import argparse
import bisect
import os
import re
import shutil
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

_SOURCE_SUFFIXES = (".c", ".cc", ".cpp", ".cxx", ".C")
_OMP_OUTLINED_RE = re.compile(r"^(?P<parent>.+)\._omp_fn\.(?P<index>\d+)$")


@dataclass(frozen=True)
class HotspotEntry:
    tid: int
    rank: int
    sample_count: int
    module_id: int
    pc_offset: int
    path: str


@dataclass
class AggregatedHotspot:
    path: str
    module_id: int
    pc_offset: int
    total_samples: int
    entries: List[HotspotEntry]


@dataclass
class Symbol:
    start: int
    end: int
    name: str
    sym_type: str


@dataclass
class ResolvedLocation:
    function: str
    location: str
    nearest_symbol: Optional[Symbol]
    has_debug_line: bool
    source_excerpt: List[str]
    disassembly: List[str]
    openmp_region: Optional["OpenMpRegion"]


@dataclass
class OpenMpRegion:
    source_path: str
    parent_function: str
    directive_line: int
    loop_line: Optional[int]
    region_index: int
    total_regions: int
    directive: str
    summary: str
    excerpt: List[str]


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("hotpc", help="Path to a .hotpc manifest")
    parser.add_argument(
        "--output",
        help="Write the text report to this path instead of stdout",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Limit the report to the hottest N unique PCs",
    )
    parser.add_argument(
        "--context-lines",
        type=int,
        default=2,
        help="Number of source lines before/after the resolved line to show",
    )
    parser.add_argument(
        "--context-bytes",
        type=lambda s: int(s, 0),
        default=0x10,
        help="Instruction context size in bytes for objdump snippets",
    )
    parser.add_argument(
        "--source-root",
        default=str(Path(__file__).resolve().parent.parent),
        help="Root directory used to heuristically search for source files",
    )
    return parser.parse_args(argv)


def require_tool(tool: str) -> None:
    if shutil.which(tool) is None:
        raise SystemExit(f"Required tool not found in PATH: {tool}")


def run_tool(args: Sequence[str]) -> str:
    try:
        proc = subprocess.run(args, check=True, capture_output=True, text=True)
    except FileNotFoundError as exc:
        raise SystemExit(f"Required tool not found: {args[0]}") from exc
    except subprocess.CalledProcessError as exc:
        detail = exc.stderr.strip() or exc.stdout.strip() or "command failed"
        cmd = " ".join(args)
        raise SystemExit(f"{cmd}: {detail}") from exc
    return proc.stdout


def parse_hotpc(path: str) -> Tuple[Dict[str, str], List[HotspotEntry]]:
    metadata: Dict[str, str] = {}
    hotspots: List[HotspotEntry] = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for raw_line in f:
            line = raw_line.rstrip("\n")
            if not line:
                continue
            if line.startswith("hotspot="):
                payload = line.split("=", 1)[1]
                parts = payload.split("\t")
                if len(parts) != 6:
                    raise SystemExit(f"Malformed hotspot entry in {path}: {line}")
                hotspots.append(
                    HotspotEntry(
                        tid=int(parts[0], 10),
                        rank=int(parts[1], 10),
                        sample_count=int(parts[2], 10),
                        module_id=int(parts[3], 10),
                        pc_offset=int(parts[4], 16),
                        path=parts[5],
                    )
                )
                continue
            if "=" in line:
                key, value = line.split("=", 1)
                metadata[key] = value
    return metadata, hotspots


def aggregate_hotspots(hotspots: Iterable[HotspotEntry]) -> List[AggregatedHotspot]:
    grouped: Dict[Tuple[str, int, int], List[HotspotEntry]] = defaultdict(list)
    for hotspot in hotspots:
        grouped[(hotspot.path, hotspot.module_id, hotspot.pc_offset)].append(hotspot)

    agg: List[AggregatedHotspot] = []
    for (path, module_id, pc_offset), entries in grouped.items():
        entries.sort(key=lambda e: (-e.sample_count, e.tid, e.rank))
        agg.append(
            AggregatedHotspot(
                path=path,
                module_id=module_id,
                pc_offset=pc_offset,
                total_samples=sum(entry.sample_count for entry in entries),
                entries=entries,
            )
        )
    agg.sort(key=lambda h: (-h.total_samples, h.path, h.pc_offset))
    return agg


def load_module_debug_status(module_path: str) -> bool:
    stdout = run_tool(["readelf", "-S", module_path])
    return ".debug_line" in stdout or ".zdebug_line" in stdout


def load_symbols(module_path: str) -> List[Symbol]:
    stdout = run_tool(["nm", "-n", module_path])
    raw_symbols: List[Tuple[int, str, str]] = []
    pattern = re.compile(r"^([0-9A-Fa-f]+)\s+([A-Za-z])\s+(.+)$")
    for line in stdout.splitlines():
        match = pattern.match(line.strip())
        if not match:
            continue
        addr = int(match.group(1), 16)
        sym_type = match.group(2)
        name = match.group(3).strip()
        if sym_type.upper() == "U":
            continue
        raw_symbols.append((addr, sym_type, name))

    symbols: List[Symbol] = []
    for i, (addr, sym_type, name) in enumerate(raw_symbols):
        next_addr = raw_symbols[i + 1][0] if i + 1 < len(raw_symbols) else addr + 1
        end = next_addr if next_addr > addr else addr + 1
        symbols.append(Symbol(start=addr, end=end, name=name, sym_type=sym_type))
    return symbols


def find_nearest_symbol(symbols: Sequence[Symbol], pc_offset: int) -> Optional[Symbol]:
    if not symbols:
        return None
    starts = [symbol.start for symbol in symbols]
    idx = bisect.bisect_right(starts, pc_offset) - 1
    if idx < 0:
        return None
    return symbols[idx]


def resolve_addr2line(module_path: str, offsets: Sequence[int]) -> Dict[int, Tuple[str, str]]:
    if not offsets:
        return {}
    cmd = ["addr2line", "-f", "-C", "-e", module_path]
    cmd.extend(hex(offset) for offset in offsets)
    stdout = run_tool(cmd)
    lines = stdout.splitlines()
    pairs: Dict[int, Tuple[str, str]] = {}
    for i, offset in enumerate(offsets):
        func = lines[2 * i].strip() if 2 * i < len(lines) else "??"
        loc = lines[2 * i + 1].strip() if 2 * i + 1 < len(lines) else "??:?"
        pairs[offset] = (func, loc)
    return pairs


def source_candidates(source_root: Path, module_path: str, parent_function: str) -> List[Path]:
    module_stem = Path(module_path).stem.lower()
    module_tokens = [token for token in re.split(r"[_\-\.]+", module_stem) if token]
    parent_pat = re.compile(rf"(?m)^[^#\n;]*\b{re.escape(parent_function)}\s*\([^;{{}}]*\)\s*\{{")

    ranked: List[Tuple[int, Path]] = []
    for path in source_root.rglob("*"):
        if not path.is_file() or path.suffix not in _SOURCE_SUFFIXES:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if "#pragma omp" not in text:
            continue
        if not parent_pat.search(text):
            continue

        stem = path.stem.lower()
        score = 0
        if stem == module_stem:
            score += 100
        if module_stem.startswith(stem) or stem.startswith(module_stem):
            score += 60
        if stem in module_stem or module_stem in stem:
            score += 30
        if stem in module_tokens:
            score += 40
        ranked.append((score, path))

    ranked.sort(key=lambda item: (-item[0], str(item[1])))
    return [path for _, path in ranked]


def function_span(text: str, function_name: str) -> Optional[Tuple[int, int]]:
    pattern = re.compile(rf"(?m)^[^#\n;]*\b{re.escape(function_name)}\s*\([^;{{}}]*\)\s*\{{")
    match = pattern.search(text)
    if not match:
        return None

    brace_pos = text.find("{", match.start())
    if brace_pos < 0:
        return None

    depth = 0
    for idx in range(brace_pos, len(text)):
        ch = text[idx]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return brace_pos, idx
    return None


def summarize_openmp_region(lines: Sequence[str], pragma_idx: int) -> Tuple[Optional[int], str]:
    summary_parts: List[str] = []
    loop_line: Optional[int] = None
    for idx in range(pragma_idx + 1, len(lines)):
        stripped = lines[idx].strip()
        if not stripped:
            continue
        if loop_line is None:
            loop_line = idx + 1
        summary_parts.append(stripped)
        if stripped.endswith(";") or stripped.endswith("{"):
            break
        if len(summary_parts) >= 2:
            break
    return loop_line, " ".join(summary_parts)


def is_outlining_omp_directive(stripped: str) -> bool:
    if not stripped.startswith("#pragma omp"):
        return False
    tail = stripped[len("#pragma omp") :].strip()
    return (
        tail.startswith("parallel")
        or tail.startswith("task")
        or tail.startswith("sections")
        or tail.startswith("teams")
        or tail.startswith("target")
    )


def collect_openmp_regions(source_path: Path, parent_function: str, context_lines: int) -> List[OpenMpRegion]:
    text = source_path.read_text(encoding="utf-8", errors="replace")
    span = function_span(text, parent_function)
    if span is None:
        return []

    lines = text.splitlines()
    start_line = text.count("\n", 0, span[0]) + 1
    end_line = text.count("\n", 0, span[1]) + 1
    fn_lines = lines[start_line - 1 : end_line]

    regions: List[OpenMpRegion] = []
    for idx, line in enumerate(fn_lines):
        stripped = line.lstrip()
        if not is_outlining_omp_directive(stripped):
            continue
        directive_line = start_line + idx
        loop_line, summary = summarize_openmp_region(fn_lines, idx)
        if loop_line is not None:
            loop_line += start_line - 1

        excerpt_start = max(0, idx - context_lines)
        excerpt_stop = min(len(fn_lines), idx + context_lines + 3)
        excerpt: List[str] = []
        for local_idx in range(excerpt_start, excerpt_stop):
            line_no = start_line + local_idx
            marker = ">" if line_no == directive_line else " "
            excerpt.append(f"{marker} {line_no:5d}: {fn_lines[local_idx]}")

        regions.append(
            OpenMpRegion(
                source_path=str(source_path),
                parent_function=parent_function,
                directive_line=directive_line,
                loop_line=loop_line,
                region_index=len(regions),
                total_regions=0,
                directive=stripped,
                summary=summary,
                excerpt=excerpt,
            )
        )

    total_regions = len(regions)
    for region in regions:
        region.total_regions = total_regions
    return regions


def infer_openmp_region(
    function_name: str,
    module_path: str,
    source_root: Path,
    context_lines: int,
) -> Optional[OpenMpRegion]:
    match = _OMP_OUTLINED_RE.match(function_name)
    if not match:
        return None

    parent_function = match.group("parent")
    outline_index = int(match.group("index"), 10)
    for source_path in source_candidates(source_root, module_path, parent_function):
        regions = collect_openmp_regions(source_path, parent_function, context_lines)
        if outline_index >= len(regions):
            continue
        source_region = regions[outline_index]
        return OpenMpRegion(
            source_path=source_region.source_path,
            parent_function=source_region.parent_function,
            directive_line=source_region.directive_line,
            loop_line=source_region.loop_line,
            region_index=source_region.region_index,
            total_regions=source_region.total_regions,
            directive=source_region.directive,
            summary=source_region.summary,
            excerpt=source_region.excerpt,
        )
    return None


def read_source_excerpt(location: str, manifest_dir: Path, radius: int) -> List[str]:
    if not location or location.endswith(":?") or location == "??:?":
        return []
    match = re.match(r"^(.*):(\d+)(?::\d+)?$", location)
    if not match:
        return []
    source_name = match.group(1)
    target_line = int(match.group(2))
    candidates = [Path(source_name)]
    if not os.path.isabs(source_name):
        candidates.append(manifest_dir / source_name)
    source_path = None
    for candidate in candidates:
        if candidate.exists():
            source_path = candidate
            break
    if source_path is None:
        return []

    lines = source_path.read_text(encoding="utf-8", errors="replace").splitlines()
    start = max(1, target_line - radius)
    stop = min(len(lines), target_line + radius)
    excerpt: List[str] = []
    for line_no in range(start, stop + 1):
        marker = ">" if line_no == target_line else " "
        excerpt.append(f"{marker} {line_no:5d}: {lines[line_no - 1]}")
    return excerpt


def read_disassembly(module_path: str, pc_offset: int, context_bytes: int) -> List[str]:
    start = max(pc_offset - context_bytes, 0)
    stop = pc_offset + context_bytes + 4
    stdout = run_tool(
        [
            "objdump",
            "-d",
            "--demangle",
            "--start-address",
            hex(start),
            "--stop-address",
            hex(stop),
            module_path,
        ]
    )
    snippet: List[str] = []
    inst_re = re.compile(r"^\s*([0-9A-Fa-f]+):\s+(.+)$")
    for line in stdout.splitlines():
        match = inst_re.match(line)
        if not match:
            continue
        addr = int(match.group(1), 16)
        marker = ">" if addr == pc_offset else " "
        snippet.append(f"{marker} 0x{addr:x}: {match.group(2).rstrip()}")
    return snippet


def resolve_module_locations(
    module_path: str,
    hotspots: Sequence[AggregatedHotspot],
    manifest_dir: Path,
    source_root: Path,
    context_lines: int,
    context_bytes: int,
) -> Dict[int, ResolvedLocation]:
    offsets = [hotspot.pc_offset for hotspot in hotspots]
    addr2line_info = resolve_addr2line(module_path, offsets)
    symbols = load_symbols(module_path)
    has_debug_line = load_module_debug_status(module_path)

    resolved: Dict[int, ResolvedLocation] = {}
    for hotspot in hotspots:
        function, location = addr2line_info.get(hotspot.pc_offset, ("??", "??:?"))
        nearest_symbol = find_nearest_symbol(symbols, hotspot.pc_offset)
        source_excerpt = read_source_excerpt(location, manifest_dir, context_lines)
        disassembly = read_disassembly(module_path, hotspot.pc_offset, context_bytes)
        openmp_region = infer_openmp_region(function, module_path, source_root, context_lines)
        resolved[hotspot.pc_offset] = ResolvedLocation(
            function=function,
            location=location,
            nearest_symbol=nearest_symbol,
            has_debug_line=has_debug_line,
            source_excerpt=source_excerpt,
            disassembly=disassembly,
            openmp_region=openmp_region,
        )
    return resolved


def format_symbol_delta(symbol: Optional[Symbol], pc_offset: int) -> str:
    if symbol is None:
        return "??"
    delta = pc_offset - symbol.start
    end = symbol.end if symbol.end > symbol.start else symbol.start + 1
    return f"{symbol.name} + 0x{delta:x} (0x{symbol.start:x}-0x{end:x})"


def build_report(
    hotpc_path: str,
    metadata: Dict[str, str],
    hotspots: Sequence[AggregatedHotspot],
    resolved_by_module: Dict[str, Dict[int, ResolvedLocation]],
) -> str:
    lines: List[str] = []
    lines.append(f"manifest: {hotpc_path}")
    if "hotspot_scope" in metadata:
        lines.append(f"hotspot_scope: {metadata['hotspot_scope']}")
    if "hotspot_main_binary" in metadata:
        lines.append(f"hotspot_main_binary: {metadata['hotspot_main_binary']}")
    lines.append(f"unique_hotspots: {len(hotspots)}")
    lines.append(f"per_thread_entries: {sum(len(hotspot.entries) for hotspot in hotspots)}")

    for idx, hotspot in enumerate(hotspots, start=1):
        resolved = resolved_by_module[hotspot.path][hotspot.pc_offset]
        seen_in = ", ".join(
            f"tid={entry.tid}/rank={entry.rank}/count={entry.sample_count}"
            for entry in hotspot.entries
        )
        lines.append("")
        lines.append(f"[{idx}] {hotspot.path} +0x{hotspot.pc_offset:x}")
        lines.append(f"  total_samples: {hotspot.total_samples}")
        lines.append(f"  seen_in: {seen_in}")
        lines.append(f"  function: {resolved.function}")
        lines.append(f"  source: {resolved.location}")
        lines.append(f"  nearest_symbol: {format_symbol_delta(resolved.nearest_symbol, hotspot.pc_offset)}")
        lines.append(f"  debug_line_info: {'yes' if resolved.has_debug_line else 'no'}")
        if resolved.openmp_region is not None:
            omp = resolved.openmp_region
            lines.append("  openmp_region_inference:")
            lines.append(f"    parent_function: {omp.parent_function}")
            lines.append(f"    source_file: {omp.source_path}")
            lines.append(f"    pragma_line: {omp.directive_line}")
            if omp.loop_line is not None:
                lines.append(f"    loop_line: {omp.loop_line}")
            lines.append(f"    directive: {omp.directive}")
            lines.append(f"    summary: {omp.summary or '(no loop summary)'}")
            lines.append(
                f"    mapping_rule: gcc usually numbers ._omp_fn.N workers in source order within the parent function"
            )
            if omp.excerpt:
                lines.append("  openmp_region_excerpt:")
                lines.extend(f"    {line}" for line in omp.excerpt)
        if resolved.source_excerpt:
            lines.append("  source_excerpt:")
            lines.extend(f"    {line}" for line in resolved.source_excerpt)
        if resolved.disassembly:
            lines.append("  disassembly:")
            lines.extend(f"    {line}" for line in resolved.disassembly)
    lines.append("")
    return "\n".join(lines)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)

    for tool in ("addr2line", "readelf", "nm", "objdump"):
        require_tool(tool)

    hotpc_path = os.path.abspath(args.hotpc)
    manifest_dir = Path(hotpc_path).parent
    source_root = Path(args.source_root).resolve()
    metadata, entries = parse_hotpc(hotpc_path)
    if not entries:
        raise SystemExit(f"No hotspot entries found in {hotpc_path}")

    hotspots = aggregate_hotspots(entries)
    if args.limit is not None:
        hotspots = hotspots[: args.limit]

    hotspots_by_module: Dict[str, List[AggregatedHotspot]] = defaultdict(list)
    for hotspot in hotspots:
        hotspots_by_module[hotspot.path].append(hotspot)

    resolved_by_module: Dict[str, Dict[int, ResolvedLocation]] = {}
    for module_path, module_hotspots in hotspots_by_module.items():
        if not os.path.exists(module_path):
            raise SystemExit(f"Module path from manifest does not exist: {module_path}")
        resolved_by_module[module_path] = resolve_module_locations(
            module_path,
            module_hotspots,
            manifest_dir,
            source_root,
            args.context_lines,
            args.context_bytes,
        )

    report = build_report(hotpc_path, metadata, hotspots, resolved_by_module)
    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(report, encoding="utf-8")
    else:
        sys.stdout.write(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
