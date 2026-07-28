#!/usr/bin/env python3
"""Analyze whether first-stage ARM SPE hotspots access a single data VA."""

from __future__ import annotations

import argparse
import glob
import re
import struct
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple


PC_VALID = 1 << 0
DATA_VA_VALID = 1 << 6


@dataclass(frozen=True)
class ModuleMap:
    module_id: int
    path: str
    vm_start: int
    vm_end: int
    file_offset: int


@dataclass(frozen=True)
class Hotspot:
    tid: int
    rank: int
    sample_count: int
    module_id: int
    pc_offset: int
    path: str


@dataclass
class HotspotVaStats:
    hotspot: Hotspot
    matched_samples: int = 0
    pc_valid_samples: int = 0
    va_valid_samples: int = 0
    va_invalid_samples: int = 0
    va_counts: Counter[int] = field(default_factory=Counter)

    @property
    def unique_va_count(self) -> int:
        return len(self.va_counts)

    @property
    def single_va(self) -> bool:
        return self.va_valid_samples > 0 and self.unique_va_count == 1


def parse_int(value: str) -> int:
    return int(value, 16) if value.lower().startswith("0x") else int(value, 10)


def parse_info(path: Path) -> Tuple[Dict[str, str], List[ModuleMap]]:
    meta: Dict[str, str] = {}
    modules: List[ModuleMap] = []
    with path.open(encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.rstrip("\n")
            if not line or "=" not in line:
                continue
            key, value = line.split("=", 1)
            if key == "module_map":
                parts = value.split("\t")
                if len(parts) < 5:
                    raise SystemExit(f"malformed module_map entry in {path}: {line}")
                modules.append(
                    ModuleMap(
                        module_id=int(parts[0], 10),
                        path=parts[1],
                        vm_start=parse_int(parts[2]),
                        vm_end=parse_int(parts[3]),
                        file_offset=parse_int(parts[4]),
                    )
                )
            else:
                meta[key] = value
    return meta, modules


def parse_hotpc(path: Path) -> Tuple[Dict[str, str], List[Hotspot]]:
    meta: Dict[str, str] = {}
    hotspots: List[Hotspot] = []
    with path.open(encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.rstrip("\n")
            if not line or "=" not in line:
                continue
            key, value = line.split("=", 1)
            if key != "hotspot":
                meta[key] = value
                continue
            parts = value.split("\t")
            if len(parts) < 6:
                raise SystemExit(f"malformed hotspot entry in {path}: {line}")
            hotspots.append(
                Hotspot(
                    tid=int(parts[0], 10),
                    rank=int(parts[1], 10),
                    sample_count=int(parts[2], 10),
                    module_id=int(parts[3], 10),
                    pc_offset=parse_int(parts[4]),
                    path=parts[5],
                )
            )
    return meta, hotspots


def default_sample_paths(info_path: Path) -> List[Path]:
    name = info_path.name
    prefix = info_path.with_name(name[: -len(".info")]) if name.endswith(".info") else info_path
    return sorted(prefix.parent.glob(prefix.name + ".t*.sample*"))


def expand_sample_args(patterns: Optional[Sequence[str]], info_path: Path) -> List[Path]:
    if not patterns:
        return default_sample_paths(info_path)
    paths: List[Path] = []
    for pattern in patterns:
        expanded = sorted(Path(p) for p in glob.glob(pattern))
        if expanded:
            paths.extend(expanded)
        else:
            paths.append(Path(pattern))
    return sorted(dict.fromkeys(paths))


def tid_from_sample_path(path: Path) -> Optional[int]:
    match = re.search(r"\.t(\d+)\.sample\d+$", path.name)
    return int(match.group(1), 10) if match else None


def sample_unpacker(fields: Sequence[str], record_bytes: int) -> struct.Struct:
    if len(fields) * 8 != record_bytes:
        raise SystemExit(
            f"sample_record_bytes={record_bytes} does not match {len(fields)} 64-bit fields"
        )
    return struct.Struct("<" + "Q" * len(fields))


def pc_to_key(pc: int, modules: Sequence[ModuleMap]) -> Optional[Tuple[int, int]]:
    for module in modules:
        if module.vm_start <= pc < module.vm_end:
            return module.module_id, pc - module.vm_start + module.file_offset
    return None


def analyze_samples(
    sample_paths: Sequence[Path],
    fields: Sequence[str],
    record_bytes: int,
    modules: Sequence[ModuleMap],
    hotspots: Sequence[Hotspot],
) -> Tuple[List[HotspotVaStats], Dict[str, int]]:
    unpacker = sample_unpacker(fields, record_bytes)
    field_index = {name: i for i, name in enumerate(fields)}
    required = {"pc", "data_va", "flags"}
    missing = sorted(required - set(field_index))
    if missing:
        raise SystemExit(
            "sample format does not contain required VA fields: "
            + ",".join(missing)
            + "; rerun stage1 with a VA-enabled librd.so"
        )

    stats = [HotspotVaStats(hotspot=h) for h in hotspots]
    by_tid_key: Dict[Tuple[int, int, int], List[HotspotVaStats]] = {}
    by_key: Dict[Tuple[int, int], List[HotspotVaStats]] = {}
    for item in stats:
        key = (item.hotspot.module_id, item.hotspot.pc_offset)
        by_tid_key.setdefault((item.hotspot.tid, *key), []).append(item)
        by_key.setdefault(key, []).append(item)

    totals = {
        "sample_files": 0,
        "sample_records": 0,
        "pc_valid_records": 0,
        "data_va_valid_records": 0,
        "matched_hotspot_records": 0,
        "short_or_misaligned_files": 0,
        "unmapped_pc_records": 0,
    }

    for path in sample_paths:
        if not path.exists():
            raise SystemExit(f"sample file not found: {path}")
        data = path.read_bytes()
        if len(data) % record_bytes != 0:
            totals["short_or_misaligned_files"] += 1
        tid = tid_from_sample_path(path)
        totals["sample_files"] += 1
        usable = len(data) - (len(data) % record_bytes)
        for off in range(0, usable, record_bytes):
            values = unpacker.unpack_from(data, off)
            totals["sample_records"] += 1
            flags = values[field_index["flags"]]
            pc = values[field_index["pc"]]
            data_va = values[field_index["data_va"]]

            if flags & PC_VALID:
                totals["pc_valid_records"] += 1
            else:
                continue
            if flags & DATA_VA_VALID:
                totals["data_va_valid_records"] += 1

            key = pc_to_key(pc, modules)
            if key is None:
                totals["unmapped_pc_records"] += 1
                continue

            matches: List[HotspotVaStats] = []
            if tid is not None:
                matches = by_tid_key.get((tid, *key), [])
            else:
                matches = by_key.get(key, [])
            if not matches:
                continue

            totals["matched_hotspot_records"] += 1
            for item in matches:
                item.matched_samples += 1
                item.pc_valid_samples += 1
                if flags & DATA_VA_VALID:
                    item.va_valid_samples += 1
                    item.va_counts[data_va] += 1
                else:
                    item.va_invalid_samples += 1

    return stats, totals


def fmt_hex(value: int) -> str:
    return f"0x{value:x}"


def write_tsv(path: Path, stats: Sequence[HotspotVaStats], top_va: int) -> None:
    with path.open("w", encoding="utf-8") as out:
        out.write(
            "tid\trank\tmodule_id\tpc_offset\tpath\thotpc_sample_count\t"
            "matched_samples\tva_valid_samples\tva_invalid_samples\tunique_va_count\t"
            "single_va\ttop_va\n"
        )
        for item in stats:
            top = ",".join(
                f"{fmt_hex(va)}:{count}" for va, count in item.va_counts.most_common(top_va)
            )
            out.write(
                f"{item.hotspot.tid}\t{item.hotspot.rank}\t{item.hotspot.module_id}\t"
                f"{fmt_hex(item.hotspot.pc_offset)}\t{item.hotspot.path}\t"
                f"{item.hotspot.sample_count}\t{item.matched_samples}\t"
                f"{item.va_valid_samples}\t{item.va_invalid_samples}\t"
                f"{item.unique_va_count}\t{1 if item.single_va else 0}\t{top}\n"
            )


def write_markdown(
    path: Path,
    info_path: Path,
    hotpc_path: Path,
    sample_paths: Sequence[Path],
    fields: Sequence[str],
    record_bytes: int,
    stats: Sequence[HotspotVaStats],
    totals: Dict[str, int],
    top_va: int,
) -> None:
    with path.open("w", encoding="utf-8") as out:
        out.write("# Hotspot Data VA Analysis\n\n")
        out.write(f"- info: `{info_path}`\n")
        out.write(f"- hotpc: `{hotpc_path}`\n")
        out.write(f"- sample_files: `{len(sample_paths)}`\n")
        out.write(f"- sample_record_bytes: `{record_bytes}`\n")
        out.write(f"- sample_record_fields: `{','.join(fields)}`\n")
        for key in sorted(totals):
            out.write(f"- {key}: `{totals[key]}`\n")
        out.write("\n")

        no_va = [item for item in stats if item.va_valid_samples == 0]
        single = [item for item in stats if item.single_va]
        multi = [item for item in stats if item.va_valid_samples > 0 and not item.single_va]
        out.write("## Summary\n\n")
        out.write(f"- hotspots: `{len(stats)}`\n")
        out.write(f"- hotspots_with_no_valid_va: `{len(no_va)}`\n")
        out.write(f"- hotspots_with_single_va: `{len(single)}`\n")
        out.write(f"- hotspots_with_multiple_va: `{len(multi)}`\n")
        out.write("\n")

        out.write("## Hotspots\n\n")
        out.write(
            "| tid | rank | pc_offset | hotpc_samples | matched | valid_va | "
            "unique_va | single_va | top_va |\n"
        )
        out.write("| ---: | ---: | --- | ---: | ---: | ---: | ---: | ---: | --- |\n")
        for item in sorted(stats, key=lambda x: (x.hotspot.tid, x.hotspot.rank)):
            top = "<none>"
            if item.va_counts:
                top = "<br>".join(
                    f"`{fmt_hex(va)}`:{count}"
                    for va, count in item.va_counts.most_common(top_va)
                )
            out.write(
                f"| {item.hotspot.tid} | {item.hotspot.rank} | "
                f"`{fmt_hex(item.hotspot.pc_offset)}` | {item.hotspot.sample_count} | "
                f"{item.matched_samples} | {item.va_valid_samples} | "
                f"{item.unique_va_count} | {1 if item.single_va else 0} | {top} |\n"
            )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--info", required=True, type=Path, help="Stage1 .info file")
    parser.add_argument("--hotpc", required=True, type=Path, help="Stage1 .hotpc file")
    parser.add_argument(
        "--samples",
        nargs="*",
        help="Sample files or glob patterns; defaults to <info-prefix>.t*.sample*",
    )
    parser.add_argument("--output", type=Path, help="Markdown output path")
    parser.add_argument("--tsv", type=Path, help="TSV output path")
    parser.add_argument("--top-va", type=int, default=8, help="Top VA values to show per hotspot")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    info_path = args.info.resolve()
    hotpc_path = args.hotpc.resolve()
    metadata, modules = parse_info(info_path)
    _, hotspots = parse_hotpc(hotpc_path)
    if not modules:
        raise SystemExit(f"no module_map entries found in {info_path}")
    if not hotspots:
        raise SystemExit(f"no hotspots found in {hotpc_path}")

    fields = [f.strip() for f in metadata.get("sample_record_fields", "").split(",") if f.strip()]
    if not fields:
        raise SystemExit(f"sample_record_fields missing in {info_path}")
    record_bytes = int(metadata.get("sample_record_bytes", str(len(fields) * 8)), 10)
    sample_paths = expand_sample_args(args.samples, info_path)
    if not sample_paths:
        raise SystemExit(f"no sample files found for {info_path}")

    stats, totals = analyze_samples(sample_paths, fields, record_bytes, modules, hotspots)
    output_path = args.output or info_path.with_suffix(".hotspot_va.md")
    tsv_path = args.tsv or info_path.with_suffix(".hotspot_va.tsv")
    write_markdown(output_path, info_path, hotpc_path, sample_paths, fields, record_bytes, stats, totals, args.top_va)
    write_tsv(tsv_path, stats, args.top_va)
    print(f"wrote {output_path}")
    print(f"wrote {tsv_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
