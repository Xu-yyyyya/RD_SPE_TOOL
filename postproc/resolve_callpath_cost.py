#!/usr/bin/env python3
"""Resolve first-stage cpu-clock cost raw samples into callpath summaries.

Default mode is intentionally lightweight and keeps the historical function
callpath report.  `--emit-loop-tree` enables the M6 libclang path: source loop
regions are recovered from AST ranges and inserted into the cost call tree.
"""

from __future__ import annotations

import argparse
import ctypes
import json
import re
import shlex
import shutil
import subprocess
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

try:
    from elftools.elf.elffile import ELFFile
    from elftools.dwarf.callframe import FDE
except ImportError as exc:
    raise SystemExit("resolve_callpath_cost.py requires pyelftools") from exc


PERF_REG_ARM64_MAX = 33
PERF_REG_ARM64_LR = 30
PERF_REG_ARM64_SP = 31
PERF_REG_ARM64_PC = 32
COST_RAW_MAGIC = 0x43524452
DEFAULT_STACK_BYTES = 8192


class CostRawRecord(ctypes.LittleEndianStructure):
    _fields_ = [
        ("magic", ctypes.c_uint32),
        ("version", ctypes.c_uint16),
        ("header_size", ctypes.c_uint16),
        ("tid", ctypes.c_uint32),
        ("cpu", ctypes.c_uint32),
        ("time", ctypes.c_uint64),
        ("ip", ctypes.c_uint64),
        ("regs_mask", ctypes.c_uint64),
        ("regs", ctypes.c_uint64 * PERF_REG_ARM64_MAX),
        ("stack_size", ctypes.c_uint32),
        ("dyn_stack_size", ctypes.c_uint32),
        ("stack", ctypes.c_uint8 * DEFAULT_STACK_BYTES),
    ]


@dataclass(frozen=True)
class FrameSymbol:
    ip: int
    function: str
    file: str
    line: int
    column: int
    raw_location: str
    module: str = ""
    module_offset: int = 0
    external: bool = False

    def text(self) -> str:
        if self.external:
            module = Path(self.module).name if self.module else "external"
            return f"{self.function} [{module}] at 0x{self.module_offset:x} ({module} + 0x{self.module_offset:x})"
        loc = self.raw_location if self.raw_location else "??:?"
        return f"{self.function}@{loc}"


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


@dataclass(frozen=True)
class LoopRegion:
    loop_id: int
    kind: str
    file: str
    start_line: int
    start_column: int
    end_line: int
    end_column: int
    depth: int
    parent_loop_id: int
    function_context: str

    def label(self, source_root: Optional[Path]) -> str:
        path = display_path(self.file, source_root)
        return f"loop at {path}:{self.start_line}"

    def contains(self, file: str, line: int, column: int) -> bool:
        if normalize_path(file) != normalize_path(self.file) or line <= 0:
            return False
        loc_col = column if column > 0 else 1
        start = (self.start_line, self.start_column if self.start_column > 0 else 1)
        end = (self.end_line, self.end_column if self.end_column > 0 else 1_000_000)
        return start <= (line, loc_col) <= end


class CallTreeNode:
    def __init__(self, node_type: str, name: str, file: str = "", line: int = 0):
        self.node_type = node_type
        self.name = name
        self.file = file
        self.line = line
        self.samples = 0
        self.children: Dict[Tuple[str, str, str, int], "CallTreeNode"] = {}

    def child(self, node_type: str, name: str, file: str = "", line: int = 0) -> "CallTreeNode":
        key = (node_type, name, file, line)
        node = self.children.get(key)
        if node is None:
            node = CallTreeNode(node_type, name, file, line)
            self.children[key] = node
        return node


def normalize_path(path: str | Path) -> str:
    if not path:
        return ""
    try:
        return str(Path(path).expanduser().resolve())
    except OSError:
        return str(Path(path).expanduser())


def display_path(path: str | Path, source_root: Optional[Path]) -> str:
    p = Path(path)
    if source_root:
        try:
            return str(p.resolve().relative_to(source_root.resolve()))
        except Exception:
            pass
    return str(p)


def parse_info(path: Path) -> Dict[str, str]:
    out: Dict[str, str] = {}
    with path.open() as fh:
        for line in fh:
            line = line.strip()
            if line and "=" in line:
                key, value = line.split("=", 1)
                out[key] = value
    return out


def load_bias_from_info(path: Path) -> int:
    info = parse_info(path)
    main_binary = normalize_path(info.get("main_binary", ""))
    if main_binary:
        with path.open() as fh:
            for line in fh:
                if not line.startswith("module_map="):
                    continue
                parts = line.strip().split("=", 1)[1].split("\t")
                if len(parts) < 5:
                    continue
                if normalize_path(parts[1]) == main_binary:
                    return int(parts[2], 16) - int(parts[4], 16)

    with path.open() as fh:
        for line in fh:
            if not line.startswith("target="):
                continue
            parts = line.strip().split("\t")
            if len(parts) >= 3:
                return int(parts[2], 16) - int(parts[1], 16)
    raise ValueError(f"cannot derive load bias from module_map= or target= lines in {path}")


def parse_module_map(path: Path) -> List[ModuleMapEntry]:
    modules: List[ModuleMapEntry] = []
    with path.open() as fh:
        for line in fh:
            if not line.startswith("module_map="):
                continue
            payload = line.strip().split("=", 1)[1]
            parts = payload.split("\t")
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
                    name = sym.name
                    if value and name:
                        symbols.append((value, name))
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
    if best is None:
        return None
    return best[1]


class StackSnapshot:
    def __init__(self, rec: CostRawRecord):
        self.regs = {i: int(rec.regs[i]) for i in range(PERF_REG_ARM64_MAX)}
        self.sp = int(rec.regs[PERF_REG_ARM64_SP])
        self.pc = int(rec.regs[PERF_REG_ARM64_PC]) or int(rec.ip)
        self.stack_base = self.sp
        self.stack_size = int(rec.stack_size)
        self.stack = bytes(rec.stack[: self.stack_size])


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
        return None, PERF_REG_ARM64_LR

    @staticmethod
    def _read_word(snap: StackSnapshot, addr: int) -> Optional[int]:
        if addr < snap.stack_base or addr + 8 > snap.stack_base + snap.stack_size:
            return None
        off = addr - snap.stack_base
        return int.from_bytes(snap.stack[off : off + 8], "little")

    def unwind(self, snap: StackSnapshot, max_depth: int = 32) -> Tuple[int, ...]:
        regs = dict(snap.regs)
        regs[31] = snap.sp
        pc = snap.pc
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
                elif rtype == "REGISTER" and arg in regs:
                    new_regs[regnum] = regs[arg]

            ra_rule = row.get(ra_reg)
            if ra_rule is None:
                next_pc = regs.get(ra_reg, 0)
            elif getattr(ra_rule, "type", "") == "OFFSET":
                next_pc = self._read_word(snap, cfa_value + int(ra_rule.arg)) or 0
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
        return tuple(chain)


def load_records(paths: Iterable[Path]) -> List[CostRawRecord]:
    records: List[CostRawRecord] = []
    size = ctypes.sizeof(CostRawRecord)
    for path in paths:
        data = path.read_bytes()
        if len(data) % size != 0:
            raise ValueError(f"{path} size {len(data)} is not divisible by record size {size}")
        for off in range(0, len(data), size):
            rec = CostRawRecord.from_buffer_copy(data[off : off + size])
            if rec.magic == COST_RAW_MAGIC:
                records.append(rec)
    return records


def offset_strings(load_bias: int, chain: Tuple[int, ...]) -> List[str]:
    addrs = []
    for i, ip in enumerate(chain):
        off = ip - load_bias
        if i > 0:
            off = max(0, off - 4)
        addrs.append(f"0x{off:x}")
    return addrs


_LOC_RE = re.compile(r"^(?P<file>.*?):(?P<line>\d+)(?::(?P<column>\d+))?(?:\s.*)?$")


def parse_location(loc: str) -> Tuple[str, int, int]:
    loc = loc.strip()
    if loc in ("??:?", "??:0", ""):
        return "", 0, 0
    m = _LOC_RE.match(loc)
    if not m:
        return loc, 0, 0
    return m.group("file"), int(m.group("line")), int(m.group("column") or 0)


def frames_from_llvm_symbolizer(binary: Path, load_bias: int, chain: Tuple[int, ...]) -> Optional[List[FrameSymbol]]:
    tool = shutil.which("llvm-symbolizer")
    if not tool or not chain:
        return None
    proc = subprocess.run(
        [tool, "--inlining", "--demangle", "-e", str(binary), *offset_strings(load_bias, chain)],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if proc.returncode != 0:
        return None

    groups: List[List[str]] = []
    cur: List[str] = []
    for line in proc.stdout.splitlines():
        if line.strip() == "":
            if cur:
                groups.append(cur)
                cur = []
            continue
        cur.append(line.rstrip())
    if cur:
        groups.append(cur)
    if not groups:
        return None

    frames: List[FrameSymbol] = []
    ips = list(chain)
    for group_index, group in enumerate(groups[: len(ips)]):
        ip = ips[group_index]
        for i in range(0, len(group), 2):
            fn = group[i].strip() if i < len(group) else "??"
            loc = group[i + 1].strip() if i + 1 < len(group) else "??:?"
            file, line, column = parse_location(loc)
            frames.append(FrameSymbol(ip, fn, normalize_path(file), line, column, loc))
    return frames if frames else None


def frames_from_addr2line(binary: Path, load_bias: int, chain: Tuple[int, ...]) -> List[FrameSymbol]:
    frames: List[FrameSymbol] = []
    for ip, addr in zip(chain, offset_strings(load_bias, chain)):
        proc = subprocess.run(
            ["addr2line", "-f", "-C", "-i", "-e", str(binary), addr],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if proc.returncode != 0:
            frames.append(FrameSymbol(ip, f"0x{ip:x}", "", 0, 0, "??:?"))
            continue
        lines = proc.stdout.splitlines()
        for i in range(0, len(lines), 2):
            fn = lines[i].strip() if i < len(lines) else "??"
            loc = lines[i + 1].strip() if i + 1 < len(lines) else "??:?"
            file, line, column = parse_location(loc)
            frames.append(FrameSymbol(ip, fn, normalize_path(file), line, column, loc))
    return frames


def symbolize_frames(binary: Path, load_bias: int, chain: Tuple[int, ...]) -> List[FrameSymbol]:
    return frames_from_llvm_symbolizer(binary, load_bias, chain) or frames_from_addr2line(binary, load_bias, chain)


def symbolize(binary: Path, load_bias: int, chain: Tuple[int, ...]) -> List[str]:
    return [frame.text() for frame in symbolize_frames(binary, load_bias, chain)]


def symbolize_chain(
    binary: Path,
    load_bias: int,
    main_size: int,
    modules: Sequence[ModuleMapEntry],
    chain: Tuple[int, ...],
    frame_cache: Optional[Dict[int, List[FrameSymbol]]] = None,
    dso_symbol_cache: Optional[Dict[str, List[Tuple[int, str]]]] = None,
) -> List[FrameSymbol]:
    frames: List[FrameSymbol] = []
    frame_cache = frame_cache if frame_cache is not None else {}
    dso_symbol_cache = dso_symbol_cache if dso_symbol_cache is not None else {}
    for index, ip in enumerate(chain):
        adjusted_ip = ip - 4 if index > 0 else ip
        module = find_module(modules, adjusted_ip)
        if module is None:
            main_offset = adjusted_ip - load_bias
            if 0 <= main_offset < main_size:
                cached = frame_cache.get(adjusted_ip)
                if cached is None:
                    cached = symbolize_frames(binary, load_bias, (adjusted_ip,))
                    frame_cache[adjusted_ip] = cached
                frames.extend(cached)
            else:
                frames.append(
                    FrameSymbol(
                        ip=ip,
                        function="external frame",
                        file="",
                        line=0,
                        column=0,
                        raw_location="module_unresolved",
                        module="module_unresolved",
                        module_offset=adjusted_ip,
                        external=True,
                    )
                )
            continue

        module_offset = module.offset(adjusted_ip)
        if normalize_path(module.path) == normalize_path(binary):
            cached = frame_cache.get(adjusted_ip)
            if cached is None:
                cached = symbolize_frames(binary, load_bias, (adjusted_ip,))
                frame_cache[adjusted_ip] = cached
            frames.extend(cached)
            continue

        symbols = dso_symbol_cache.setdefault(module.path, load_function_symbols(module.path))
        function = nearest_symbol_name(symbols, module_offset) or "unknown procedure"
        frames.append(
            FrameSymbol(
                ip=ip,
                function=function,
                file="",
                line=0,
                column=0,
                raw_location="external DSO",
                module=module.path,
                module_offset=module_offset,
                external=True,
            )
        )
    return frames


def import_clang_cindex():
    try:
        from clang import cindex  # type: ignore
    except ImportError as exc:
        raise SystemExit(
            "--emit-loop-tree requires Python clang bindings. "
            "Install a libclang-compatible clang package."
        ) from exc

    candidates = [
        "/usr/lib/llvm-14/lib/libclang.so.1",
        "/usr/lib/llvm-14/lib/libclang-14.so.1",
        "/usr/lib/aarch64-linux-gnu/libclang-14.so.1",
    ]
    for candidate in candidates:
        if Path(candidate).exists():
            try:
                cindex.Config.set_library_file(candidate)
            except Exception:
                pass
            break
    try:
        cindex.Index.create()
    except Exception as exc:
        raise SystemExit(f"failed to initialize libclang: {exc}") from exc
    return cindex


def load_compile_commands(path: Optional[Path]) -> List[dict]:
    if path is None:
        raise SystemExit("--emit-loop-tree requires --compile-commands")
    with path.open() as fh:
        data = json.load(fh)
    if not isinstance(data, list):
        raise SystemExit("compile_commands.json must be a JSON array")
    return data


def command_arguments(entry: dict) -> List[str]:
    if "arguments" in entry and isinstance(entry["arguments"], list):
        return list(entry["arguments"])
    if "command" in entry:
        return shlex.split(entry["command"])
    raise SystemExit("compile command entry lacks command/arguments")


def gcc_include_dir() -> Optional[str]:
    """Return GCC's private include directory when it is available.

    libclang does not automatically inherit GCC's OpenMP include path from a
    compile command that was produced for g++.  Adding this directory lets the
    AST parser see `omp.h`, which is required for OpenMP benchmark sources.
    """

    gcc = shutil.which("g++") or shutil.which("gcc")
    if not gcc:
        return None
    try:
        proc = subprocess.run(
            [gcc, "-print-file-name=include"],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    path = proc.stdout.strip()
    if path and Path(path).is_dir():
        return path
    return None


def filtered_clang_args(entry: dict, source_file: str) -> List[str]:
    raw = command_arguments(entry)
    if raw:
        raw = raw[1:]
    directory = Path(entry.get("directory", "."))
    out: List[str] = []
    skip_next = False
    skip_with_arg = {"-o", "-MF", "-MT", "-MQ", "-include-pch"}
    drop_exact = {"-c", source_file}
    source_name = Path(source_file).name
    for arg in raw:
        if skip_next:
            skip_next = False
            continue
        if arg in skip_with_arg:
            skip_next = True
            continue
        arg_path = Path(arg)
        if (
            arg in drop_exact
            or normalize_path(arg) == normalize_path(source_file)
            or (
                not arg.startswith("-")
                and arg_path.name == source_name
                and arg_path.suffix in {".c", ".cc", ".cpp", ".cxx", ".C"}
            )
        ):
            continue
        if arg.startswith("-I") and len(arg) > 2:
            include_path = Path(arg[2:])
            if not include_path.is_absolute():
                arg = "-I" + normalize_path(directory / include_path)
        if arg.startswith("-o") and arg != "-ObjC":
            continue
        if arg in {"-MMD", "-MD", "-MP"}:
            continue
        if arg.startswith("-march=") or arg.startswith("-mcpu=") or arg.startswith("-mtune="):
            continue
        out.append(arg)
    if not any(arg.startswith("-std=") for arg in out):
        out.append("-std=c++17")
    if any(arg == "-fopenmp" or arg.startswith("-fopenmp=") for arg in out):
        include_dir = gcc_include_dir()
        if include_dir and f"-I{include_dir}" not in out:
            out.append(f"-I{include_dir}")
    return out


def compile_entry_for_file(entries: Sequence[dict], source: str) -> Optional[dict]:
    src_norm = normalize_path(source)
    src_base = Path(source).name
    for entry in entries:
        directory = Path(entry.get("directory", "."))
        file_value = Path(entry.get("file", ""))
        if not file_value.is_absolute():
            file_value = directory / file_value
        if normalize_path(file_value) == src_norm:
            return entry
    for entry in entries:
        if Path(entry.get("file", "")).name == src_base:
            return entry
    return None


def loop_kind_name(cindex, kind) -> str:
    if kind == cindex.CursorKind.FOR_STMT:
        return "for"
    if kind == cindex.CursorKind.WHILE_STMT:
        return "while"
    if kind == cindex.CursorKind.DO_STMT:
        return "do"
    if hasattr(cindex.CursorKind, "CXX_FOR_RANGE_STMT") and kind == cindex.CursorKind.CXX_FOR_RANGE_STMT:
        return "range_for"
    return "loop"


def is_function_cursor(cindex, kind) -> bool:
    function_kinds = {
        cindex.CursorKind.FUNCTION_DECL,
        cindex.CursorKind.CXX_METHOD,
        cindex.CursorKind.CONSTRUCTOR,
        cindex.CursorKind.DESTRUCTOR,
        cindex.CursorKind.FUNCTION_TEMPLATE,
    }
    return kind in function_kinds


def extract_loop_regions(
    source_files: Iterable[str],
    compile_commands: Optional[Path],
    source_root: Optional[Path],
) -> Tuple[List[LoopRegion], List[str]]:
    cindex = import_clang_cindex()
    entries = load_compile_commands(compile_commands)
    index = cindex.Index.create()
    loops: List[LoopRegion] = []
    diagnostics: List[str] = []
    seen_tus = set()
    wanted_sources = {normalize_path(s) for s in source_files if s}
    source_root_norm = normalize_path(source_root) if source_root else ""
    loop_kinds = {
        cindex.CursorKind.FOR_STMT,
        cindex.CursorKind.WHILE_STMT,
        cindex.CursorKind.DO_STMT,
    }
    if hasattr(cindex.CursorKind, "CXX_FOR_RANGE_STMT"):
        loop_kinds.add(cindex.CursorKind.CXX_FOR_RANGE_STMT)

    for source in sorted({normalize_path(s) for s in source_files if s and Path(s).exists()}):
        entry = compile_entry_for_file(entries, source)
        if entry is None:
            diagnostics.append(f"no compile command for {source}")
            continue
        tu_file = normalize_path(Path(entry.get("directory", ".")) / entry.get("file", source))
        if tu_file in seen_tus:
            continue
        seen_tus.add(tu_file)
        args = filtered_clang_args(entry, tu_file)
        tu = index.parse(tu_file, args=args, options=0)
        for diag in tu.diagnostics:
            diagnostics.append(str(diag))

        def visit(cursor, loop_stack: List[int], function_context: str) -> None:
            nonlocal loops
            kind = cursor.kind
            if is_function_cursor(cindex, kind):
                function_context = cursor.spelling or cursor.displayname or function_context
            new_stack = loop_stack
            if kind in loop_kinds:
                start = cursor.extent.start
                end = cursor.extent.end
                if start.file and end.file:
                    file_norm = normalize_path(str(start.file))
                    if wanted_sources and file_norm not in wanted_sources:
                        if not source_root_norm or not file_norm.startswith(source_root_norm + "/"):
                            for child in cursor.get_children():
                                visit(child, loop_stack, function_context)
                            return
                    loop_id = len(loops) + 1
                    parent = loop_stack[-1] if loop_stack else 0
                    loops.append(
                        LoopRegion(
                            loop_id=loop_id,
                            kind=loop_kind_name(cindex, kind),
                            file=file_norm,
                            start_line=start.line,
                            start_column=start.column,
                            end_line=end.line,
                            end_column=end.column,
                            depth=len(loop_stack),
                            parent_loop_id=parent,
                            function_context=function_context,
                        )
                    )
                    new_stack = loop_stack + [loop_id]
            for child in cursor.get_children():
                visit(child, new_stack, function_context)

        visit(tu.cursor, [], "")

    return loops, diagnostics


def find_innermost_loop(frame: FrameSymbol, loops_by_file: Dict[str, List[LoopRegion]]) -> Optional[LoopRegion]:
    candidates = loops_by_file.get(normalize_path(frame.file), [])
    best: Optional[LoopRegion] = None
    for loop in candidates:
        if not loop.contains(frame.file, frame.line, frame.column):
            continue
        if best is None or loop.depth > best.depth or (
            loop.depth == best.depth
            and (loop.end_line - loop.start_line) < (best.end_line - best.start_line)
        ):
            best = loop
    return best


def insert_calltree_sample(
    root: CallTreeNode,
    frames: Sequence[FrameSymbol],
    loops_by_file: Dict[str, List[LoopRegion]],
    source_root: Optional[Path],
) -> bool:
    root.samples += 1
    node = root
    matched_loop = False
    previous = ("", "")
    for frame in reversed(frames):
        if frame.function == "??" and not frame.file:
            continue
        if frame.external:
            fn_node_name = frame.text()
        else:
            fn_name = frame.function or f"0x{frame.ip:x}"
            loc_text = display_path(frame.file, source_root) if frame.file else ""
            fn_node_name = fn_name if not loc_text or frame.line <= 0 else f"{fn_name} [{loc_text}:{frame.line}]"
        key = ("function", fn_node_name)
        if key != previous:
            node = node.child("function", fn_node_name, frame.file, frame.line)
            node.samples += 1
            previous = key
        loop = find_innermost_loop(frame, loops_by_file)
        if loop:
            matched_loop = True
            label = f"{loop.label(source_root)} ({loop.kind})"
            key = ("loop", label)
            if key != previous:
                node = node.child("loop", label, loop.file, loop.start_line)
                node.samples += 1
                previous = key
    return matched_loop


def write_calltree_tsv(path: Path, root: CallTreeNode, total: int) -> None:
    with path.open("w") as out:
        out.write("depth\tnode_type\tname\tfile\tline\tsamples\tcpu_time_share\tparent_path\n")

        def rec(node: CallTreeNode, depth: int, parent_path: str) -> None:
            share = node.samples / total if total else 0.0
            out.write(
                f"{depth}\t{node.node_type}\t{node.name}\t{node.file}\t{node.line}\t"
                f"{node.samples}\t{share:.6f}\t{parent_path}\n"
            )
            next_parent = f"{parent_path}/{node.name}" if parent_path else node.name
            for child in sorted(node.children.values(), key=lambda c: (-c.samples, c.name)):
                rec(child, depth + 1, next_parent)

        rec(root, 0, "")


def markdown_calltree(root: CallTreeNode, total: int, top: int) -> str:
    lines: List[str] = []

    def rec(node: CallTreeNode, depth: int) -> None:
        share = node.samples / total if total else 0.0
        indent = "  " * depth
        lines.append(f"{indent}- {node.name}  {node.samples}  {share:.1%}")
        children = sorted(node.children.values(), key=lambda c: (-c.samples, c.name))
        for child in children[:top]:
            rec(child, depth + 1)

    rec(root, 0)
    return "\n".join(lines)


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
    parser.add_argument("--cost-raw", required=True, nargs="+", type=Path)
    parser.add_argument("--output-prefix", required=True, type=Path)
    parser.add_argument("--top", type=int, default=30)
    parser.add_argument("--source-root", type=Path)
    parser.add_argument("--compile-commands", type=Path)
    parser.add_argument("--emit-loop-tree", action="store_true")
    parser.add_argument(
        "--max-samples",
        type=int,
        default=0,
        help="Uniformly subsample at most this many raw records for fast validation; 0 means all records.",
    )
    args = parser.parse_args()

    info = parse_info(args.info)
    binary = Path(info.get("main_binary", ""))
    if not binary.exists():
        raise SystemExit(f"main_binary not found: {binary}")
    load_bias = load_bias_from_info(args.info)
    module_info = args.module_info or args.info
    modules = parse_module_map(module_info)
    main_size = elf_load_size(binary)
    records = load_records(args.cost_raw)
    total_records_available = len(records)
    if args.max_samples < 0:
        raise SystemExit("--max-samples must be non-negative")
    if args.max_samples and len(records) > args.max_samples:
        # Keep a deterministic uniform subset across all raw files instead of
        # taking the first N records, which would overrepresent early threads.
        original = records
        count = args.max_samples
        records = [original[(i * len(original)) // count] for i in range(count)]
    source_root = args.source_root.resolve() if args.source_root else None

    unwinder = CfiUnwinder(binary, load_bias)
    counts: Counter[Tuple[str, ...]] = Counter()
    tid_counts: Counter[int] = Counter()
    sample_frames: List[List[FrameSymbol]] = []
    source_files = set()
    frame_cache: Dict[int, List[FrameSymbol]] = {}
    dso_symbol_cache: Dict[str, List[Tuple[int, str]]] = {}
    try:
        for rec in records:
            snap = StackSnapshot(rec)
            chain = unwinder.unwind(snap)
            if not chain:
                continue
            frames = symbolize_chain(binary, load_bias, main_size, modules, chain, frame_cache, dso_symbol_cache)
            if not frames:
                continue
            key = tuple(frame.text() for frame in frames)
            counts[key] += 1
            sample_frames.append(frames)
            tid_counts[int(rec.tid)] += 1
            for frame in frames:
                if frame.file:
                    source_files.add(frame.file)
    finally:
        unwinder.close()

    txt_path = args.output_prefix.with_suffix(".cost.callpaths.txt")
    md_path = args.output_prefix.with_suffix(".cost.summary.md")
    calltree_tsv_path = args.output_prefix.with_suffix(".cost.calltree.tsv")
    calltree_md_path = args.output_prefix.with_suffix(".cost.calltree.md")
    total = sum(counts.values())

    with txt_path.open("w") as out:
        out.write("samples\tfraction\tcallchain\n")
        for chain_key, count in counts.most_common(args.top):
            out.write(f"{count}\t{(count / total if total else 0):.6f}\t" + " <- ".join(chain_key) + "\n")

    loop_stats = {
        "enabled": False,
        "loop_region_count": 0,
        "loop_matched_samples": 0,
        "no_loop_samples": 0,
        "diagnostics": [],
    }
    loop_tree_markdown = ""
    if args.emit_loop_tree:
        loops, diagnostics = extract_loop_regions(source_files, args.compile_commands, source_root)
        loops_by_file: Dict[str, List[LoopRegion]] = {}
        for loop in loops:
            loops_by_file.setdefault(normalize_path(loop.file), []).append(loop)
        for file_loops in loops_by_file.values():
            file_loops.sort(key=lambda l: (l.start_line, l.start_column, -l.depth))

        root = CallTreeNode("program_root", "<program root>")
        matched = 0
        for frames in sample_frames:
            if insert_calltree_sample(root, frames, loops_by_file, source_root):
                matched += 1
        write_calltree_tsv(calltree_tsv_path, root, total)
        loop_tree_markdown = markdown_calltree(root, total, args.top)
        with calltree_md_path.open("w") as out:
            out.write("# Loop-Aware Call Tree\n\n")
            out.write("```text\n")
            out.write(loop_tree_markdown)
            out.write("\n```\n")
        loop_stats.update(
            {
                "enabled": True,
                "loop_region_count": len(loops),
                "loop_matched_samples": matched,
                "no_loop_samples": max(0, len(sample_frames) - matched),
                "diagnostics": diagnostics,
            }
        )

    with md_path.open("w") as out:
        out.write("# Callpath Cost Summary\n\n")
        out.write(f"- total_records: {len(records)}\n")
        out.write(f"- total_records_available: {total_records_available}\n")
        out.write(f"- max_samples: {args.max_samples}\n")
        out.write(f"- unwindable_records: {total}\n")
        out.write(f"- unique_callpaths: {len(counts)}\n")
        out.write(f"- binary: `{binary}`\n")
        out.write(f"- module_map_source: `{module_info}`\n")
        out.write(f"- module_map_entries: `{len(modules)}`\n")
        out.write(f"- symbolizer: `llvm-symbolizer` with `addr2line` fallback\n\n")
        out.write("## Per Thread Samples\n\n")
        out.write("| tid | samples |\n|---:|---:|\n")
        for tid, count in sorted(tid_counts.items()):
            out.write(f"| {tid} | {count} |\n")
        out.write("\n")

        if args.emit_loop_tree:
            out.write("## Loop Resolution Stats\n\n")
            out.write(f"- source_root: `{source_root}`\n")
            out.write(f"- compile_commands: `{args.compile_commands}`\n")
            out.write(f"- loop_region_count: {loop_stats['loop_region_count']}\n")
            out.write(f"- loop_matched_samples: {loop_stats['loop_matched_samples']}\n")
            out.write(f"- no_loop_samples: {loop_stats['no_loop_samples']}\n")
            diagnostics = loop_stats["diagnostics"]
            if diagnostics:
                out.write("- libclang_diagnostics:\n")
                for diag in diagnostics[:20]:
                    out.write(f"  - `{diag}`\n")
            out.write("\n## Loop-Aware Call Tree\n\n")
            out.write("```text\n")
            out.write(loop_tree_markdown)
            out.write("\n```\n")

    print(f"wrote {txt_path}")
    print(f"wrote {md_path}")
    if args.emit_loop_tree:
        print(f"wrote {calltree_tsv_path}")
        print(f"wrote {calltree_md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
