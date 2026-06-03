#!/usr/bin/env python3
"""Resolve targeted_rd DWARF raw events into use-reuse callchain reports."""

from __future__ import annotations

import argparse
import ctypes
import subprocess
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

try:
    from elftools.elf.elffile import ELFFile
    from elftools.dwarf.callframe import FDE
except ImportError as exc:
    raise SystemExit("resolve_dwarf_pairs.py requires pyelftools") from exc


RD_WPCTL_LOG2_BUCKETS = 64
RD_WPCTL_MAX_DWARF_STACK_BYTES = 8192


@dataclass(frozen=True)
class ModuleMapEntry:
    module_id: int
    path: str
    vm_start: int
    vm_end: int
    file_offset: int

    def contains(self, ip: int) -> bool:
        return self.vm_start <= ip < self.vm_end

    def offset(self, ip: int) -> int:
        return ip - self.vm_start + self.file_offset


class Snapshot(ctypes.LittleEndianStructure):
    _fields_ = [
        ("regs", ctypes.c_uint64 * 31),
        ("sp", ctypes.c_uint64),
        ("pc", ctypes.c_uint64),
        ("pstate", ctypes.c_uint64),
        ("stack_base", ctypes.c_uint64),
        ("stack_size", ctypes.c_uint32),
        ("reserved0", ctypes.c_uint32),
        ("stack", ctypes.c_uint8 * RD_WPCTL_MAX_DWARF_STACK_BYTES),
    ]


class DwarfEvent(ctypes.LittleEndianStructure):
    _fields_ = [
        ("thread_index", ctypes.c_uint32),
        ("event_index", ctypes.c_uint32),
        ("used", ctypes.c_uint8),
        ("bucket", ctypes.c_uint8),
        ("reserved0", ctypes.c_uint8 * 6),
        ("tid", ctypes.c_int32),
        ("target_index", ctypes.c_uint32),
        ("seed_pc_offset", ctypes.c_uint64),
        ("seed_pc", ctypes.c_uint64),
        ("reuse_pc", ctypes.c_uint64),
        ("seed_access", ctypes.c_uint64),
        ("hit_access", ctypes.c_uint64),
        ("delta", ctypes.c_uint64),
        ("seed", Snapshot),
        ("reuse", Snapshot),
    ]


def parse_info(path: Path) -> Dict[str, str]:
    out: Dict[str, str] = {}
    with path.open() as fh:
        for line in fh:
            line = line.strip()
            if line and "=" in line:
                k, v = line.split("=", 1)
                out[k] = v
    return out


def load_bias_from_info(path: Path) -> int:
    with path.open() as fh:
        for line in fh:
            if not line.startswith("target="):
                continue
            parts = line.strip().split("\t")
            if len(parts) >= 3:
                return int(parts[2], 16) - int(parts[1], 16)
    raise ValueError(f"no target= lines found in {path}")


def parse_module_map(path: Path) -> List[ModuleMapEntry]:
    modules: List[ModuleMapEntry] = []
    with path.open() as fh:
        for line in fh:
            if not line.startswith("module_map="):
                continue
            parts = line.strip().split("=", 1)[1].split("\t")
            if len(parts) < 5:
                continue
            modules.append(
                ModuleMapEntry(
                    module_id=int(parts[0], 10),
                    path=parts[1],
                    vm_start=int(parts[2], 16),
                    vm_end=int(parts[3], 16),
                    file_offset=int(parts[4], 16),
                )
            )
    modules.sort(key=lambda m: (m.vm_start, m.vm_end))
    return modules


def find_module(modules: Sequence[ModuleMapEntry], ip: int) -> Optional[ModuleMapEntry]:
    matches = [module for module in modules if module.contains(ip)]
    if not matches:
        return None
    executable = [module for module in matches if module.path and not module.path.startswith("[")]
    return executable[0] if executable else matches[0]


def elf_load_size(binary: Path) -> int:
    with binary.open("rb") as fh:
        elf = ELFFile(fh)
        end = 0
        for segment in elf.iter_segments():
            if segment.header.p_type != "PT_LOAD":
                continue
            end = max(end, int(segment.header.p_vaddr) + int(segment.header.p_memsz))
        return end


def load_function_symbols(module_path: str) -> List[Tuple[int, str]]:
    path = Path(module_path)
    if not path.exists() or path.name.startswith("["):
        return []
    symbols: List[Tuple[int, str]] = []
    try:
        with path.open("rb") as fh:
            elf = ELFFile(fh)
            for section_name in (".symtab", ".dynsym"):
                section = elf.get_section_by_name(section_name)
                if section is None:
                    continue
                for sym in section.iter_symbols():
                    info = sym.entry.get("st_info")
                    if info and info.get("type") != "STT_FUNC":
                        continue
                    value = int(sym.entry.st_value)
                    if value and sym.name:
                        symbols.append((value, sym.name))
    except Exception:
        return []
    symbols.sort()
    return symbols


def nearest_symbol_name(symbols: Sequence[Tuple[int, str]], offset: int) -> Optional[str]:
    best: Optional[Tuple[int, str]] = None
    for value, name in symbols:
        if value <= offset:
            best = (value, name)
        else:
            break
    return best[1] if best else None


class CfiUnwinder:
    def __init__(self, binary: Path, load_bias: int):
        self.binary = binary
        self.load_bias = load_bias
        self.file = binary.open("rb")
        self.elf = ELFFile(self.file)
        self.dwarf = self.elf.get_dwarf_info()
        self.fdes = []
        for entry in self.dwarf.EH_CFI_entries():
            if isinstance(entry, FDE):
                start = int(entry.header["initial_location"])
                end = start + int(entry.header["address_range"])
                self.fdes.append((start, end, entry))

    def close(self) -> None:
        self.file.close()

    def _find_row(self, pc_offset: int):
        for start, end, fde in self.fdes:
            if start <= pc_offset < end:
                row = None
                for candidate in fde.get_decoded().table:
                    if int(candidate["pc"]) <= pc_offset:
                        row = candidate
                    else:
                        break
                return row, fde.cie.header["return_address_register"]
        return None, 30

    @staticmethod
    def _read_word(snap: Snapshot, addr: int) -> int | None:
        base = int(snap.stack_base)
        size = int(snap.stack_size)
        if addr < base or addr + 8 > base + size:
            return None
        off = addr - base
        data = bytes(snap.stack[off : off + 8])
        return int.from_bytes(data, "little")

    def unwind(self, snap: Snapshot, max_depth: int = 32) -> List[int]:
        regs = {i: int(snap.regs[i]) for i in range(31)}
        regs[31] = int(snap.sp)
        pc = int(snap.pc)
        chain: List[int] = []

        for depth in range(max_depth):
            if not pc:
                break
            chain.append(pc)
            pc_offset = pc - self.load_bias
            if depth > 0:
                pc_offset -= 4
            row, ra_reg = self._find_row(pc_offset)
            if row is None:
                break

            cfa = row["cfa"]
            cfa_reg = getattr(cfa, "reg", None)
            cfa_off = getattr(cfa, "offset", None)
            if cfa_reg is None or cfa_off is None or cfa_reg not in regs:
                break
            cfa_value = regs[cfa_reg] + cfa_off

            new_regs = dict(regs)
            new_regs[31] = cfa_value
            for regnum, rule in row.items():
                if not isinstance(regnum, int):
                    continue
                rtype = getattr(rule, "type", "")
                arg = getattr(rule, "arg", None)
                if rtype == "OFFSET":
                    value = self._read_word(snap, cfa_value + int(arg))
                    if value is not None:
                        new_regs[regnum] = value
                elif rtype == "SAME_VALUE":
                    pass
                elif rtype == "REGISTER" and arg in regs:
                    new_regs[regnum] = regs[arg]

            ra_rule = row.get(ra_reg)
            if ra_rule is None:
                next_pc = regs.get(ra_reg, 0)
            elif getattr(ra_rule, "type", "") == "OFFSET":
                value = self._read_word(snap, cfa_value + int(ra_rule.arg))
                next_pc = value or 0
            elif getattr(ra_rule, "type", "") == "REGISTER":
                next_pc = regs.get(int(ra_rule.arg), 0)
            elif getattr(ra_rule, "type", "") == "SAME_VALUE":
                next_pc = regs.get(ra_reg, 0)
            else:
                next_pc = 0
            if next_pc == pc:
                break
            regs = new_regs
            pc = next_pc
        return chain


def load_events(paths: Iterable[Path]) -> List[DwarfEvent]:
    events: List[DwarfEvent] = []
    size = ctypes.sizeof(DwarfEvent)
    for path in paths:
        data = path.read_bytes()
        if len(data) % size != 0:
            raise ValueError(f"{path} size {len(data)} is not divisible by event size {size}")
        for off in range(0, len(data), size):
            event = DwarfEvent.from_buffer_copy(data[off : off + size])
            if event.used:
                events.append(event)
    return events


def symbolize_frames(binary: Path, load_bias: int, chain: Tuple[int, ...]) -> List[Tuple[int, str]]:
    if not chain:
        return []
    addrs = []
    for i, ip in enumerate(chain):
        off = ip - load_bias
        if i > 0:
            off = max(0, off - 4)
        addrs.append(f"0x{off:x}")
    proc = subprocess.run(
        ["addr2line", "-f", "-C", "-e", str(binary), *addrs],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if proc.returncode != 0:
        return [(ip, f"0x{ip:x}") for ip in chain]
    lines = proc.stdout.splitlines()
    out = []
    for idx, i in enumerate(range(0, len(lines), 2)):
        fn = lines[i].strip() if i < len(lines) else "??"
        loc = lines[i + 1].strip() if i + 1 < len(lines) else "??:?"
        out.append((chain[idx], f"{fn}@{loc}"))
    return out


def symbolize(binary: Path, load_bias: int, chain: Tuple[int, ...]) -> List[str]:
    return [text for _ip, text in symbolize_frames(binary, load_bias, chain)]


def symbolize_chain(
    binary: Path,
    load_bias: int,
    main_size: int,
    modules: Sequence[ModuleMapEntry],
    chain: Tuple[int, ...],
) -> List[Tuple[int, str]]:
    frames: List[Tuple[int, str]] = []
    symbol_cache: Dict[str, List[Tuple[int, str]]] = {}
    binary_norm = str(binary.expanduser().resolve())
    for index, ip in enumerate(chain):
        adjusted_ip = ip - 4 if index > 0 else ip
        module = find_module(modules, adjusted_ip)
        if module is None:
            main_offset = adjusted_ip - load_bias
            if 0 <= main_offset < main_size:
                frames.extend(symbolize_frames(binary, load_bias, (adjusted_ip,)))
            else:
                frames.append((ip, f"external frame [module_unresolved] at 0x{adjusted_ip:x} (module_unresolved + 0x{adjusted_ip:x})"))
            continue

        module_offset = module.offset(adjusted_ip)
        module_path = module.path
        try:
            module_norm = str(Path(module_path).expanduser().resolve())
        except OSError:
            module_norm = module_path
        if module_norm == binary_norm:
            frames.extend(symbolize_frames(binary, load_bias, (adjusted_ip,)))
            continue

        symbols = symbol_cache.setdefault(module_path, load_function_symbols(module_path))
        function = nearest_symbol_name(symbols, module_offset) or "unknown procedure"
        module_name = Path(module_path).name if module_path else "external"
        frames.append((ip, f"{function} [{module_name}] at 0x{module_offset:x} ({module_name} + 0x{module_offset:x})"))
    return frames


def render_call_tree(frames: List[Tuple[int, str]], hit_label: str, hit_pc: int) -> List[str]:
    """Render a leaf-first unwind chain as a root-to-hit ASCII call tree."""
    if not frames:
        return ["  (empty callchain)"]

    root_to_leaf = list(reversed(frames))
    while len(root_to_leaf) > 1 and root_to_leaf[0][1].startswith("??@"):
        root_to_leaf.pop(0)
    lines: List[str] = []
    for depth, (ip, text) in enumerate(root_to_leaf):
        is_hit = ip == hit_pc or depth == len(root_to_leaf) - 1
        if depth == 0:
            prefix = ""
        else:
            prefix = "    " * (depth - 1) + "`-- "
        suffix = f"  [{hit_label} pc=0x{hit_pc:x}]" if is_hit else ""
        lines.append(f"{prefix}{text} (0x{ip:x}){suffix}")
    return lines


def chain_key(chain: List[int]) -> Tuple[int, ...]:
    return tuple(chain)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--info", required=True, type=Path)
    parser.add_argument(
        "--module-info",
        type=Path,
        help=(
            "Optional .info file containing module_map= entries. Prefer the "
            "same-run .rd2.info when it has mappings; a first-stage .info is "
            "only address-accurate if mappings are stable across runs."
        ),
    )
    parser.add_argument("--raw", required=True, nargs="+", type=Path)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--output-prefix", type=Path)
    parser.add_argument("--top", type=int, default=20)
    args = parser.parse_args()

    info = parse_info(args.info)
    if info.get("callchain_mode") != "dwarf":
        raise SystemExit("input is not a DWARF callchain run")
    binary = args.binary or Path(info.get("main_binary", ""))
    if not binary.exists():
        raise SystemExit(f"binary not found: {binary}")
    prefix = args.output_prefix or args.info.with_suffix("")
    load_bias = load_bias_from_info(args.info)
    module_info = args.module_info or args.info
    modules = parse_module_map(module_info)
    main_size = elf_load_size(binary)
    events = load_events(args.raw)

    unwinder = CfiUnwinder(binary, load_bias)
    try:
        grouped: Dict[Tuple[Tuple[int, ...], int, Tuple[int, ...], int], Dict[Tuple[int, int], int]] = defaultdict(lambda: defaultdict(int))
        for event in events:
            seed_chain = chain_key(unwinder.unwind(event.seed))
            reuse_chain = chain_key(unwinder.unwind(event.reuse))
            bucket = (0 if event.bucket == 0 else (1 << (event.bucket - 1)),
                      0 if event.bucket == 0 else ((1 << event.bucket) - 1))
            if event.bucket == 1:
                bucket = (1, 1)
            grouped[(seed_chain, int(event.seed_pc_offset), reuse_chain, int(event.reuse_pc))][bucket] += 1

        hist_path = Path(str(prefix) + ".dwarf.pair_context.hist.log2.txt")
        report_path = Path(str(prefix) + ".dwarf.long_rd.report.md")
        hist_path.parent.mkdir(parents=True, exist_ok=True)
        with hist_path.open("w") as out:
            out.write("seed_chain\treuse_chain\tseed_pc_offset\treuse_pc\tbucket_lo\tbucket_hi\tcount\n")
            for (seed_chain, seed_off, reuse_chain, reuse_pc), buckets in grouped.items():
                seed_text = " <- ".join(f"0x{x:x}" for x in seed_chain)
                reuse_text = " <- ".join(f"0x{x:x}" for x in reuse_chain)
                for (lo, hi), count in sorted(buckets.items()):
                    out.write(f"{seed_text}\t{reuse_text}\t0x{seed_off:x}\t0x{reuse_pc:x}\t{lo}\t{hi}\t{count}\n")

        ranked = sorted(grouped.items(), key=lambda item: sum(item[1].values()), reverse=True)
        with report_path.open("w") as out:
            out.write("# DWARF Use-Reuse Calling Context Report\n\n")
            out.write(f"- events: {len(events)}\n")
            out.write(f"- groups: {len(grouped)}\n\n")
            out.write(f"- module_map_source: `{module_info}`\n")
            out.write(f"- module_map_entries: `{len(modules)}`\n\n")
            for rank, ((seed_chain, seed_off, reuse_chain, reuse_pc), buckets) in enumerate(ranked[: args.top], 1):
                out.write(f"## Pair {rank}\n\n")
                out.write(f"- seed_pc_offset: `0x{seed_off:x}`\n")
                out.write(f"- reuse_pc: `0x{reuse_pc:x}`\n")
                out.write(f"- count: `{sum(buckets.values())}`\n")
                out.write("- buckets: " + ", ".join(f"[{lo},{hi}]={c}" for (lo, hi), c in sorted(buckets.items())) + "\n\n")
                out.write("Use-side calling context tree:\n\n")
                out.write("```text\n")
                seed_frames = symbolize_chain(binary, load_bias, main_size, modules, seed_chain)
                for line in render_call_tree(seed_frames, "USE HIT", seed_chain[0] if seed_chain else 0):
                    out.write(line + "\n")
                out.write("```\n\n")

                out.write("Reuse-side calling context tree:\n\n")
                out.write("```text\n")
                reuse_frames = symbolize_chain(binary, load_bias, main_size, modules, reuse_chain)
                for line in render_call_tree(reuse_frames, "REUSE HIT", reuse_chain[0] if reuse_chain else 0):
                    out.write(line + "\n")
                out.write("```\n\n")

                out.write("Leaf-to-root summary:\n\n")
                out.write("- use: " + " <- ".join(text for _ip, text in seed_frames) + "\n")
                out.write("- reuse: " + " <- ".join(text for _ip, text in reuse_frames) + "\n")
                out.write("\n")
    finally:
        unwinder.close()

    print(f"wrote {hist_path}")
    print(f"wrote {report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
