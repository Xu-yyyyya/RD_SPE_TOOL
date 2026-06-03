#!/usr/bin/env python3
"""Resolve first-stage `.hotpc` candidates into source-oriented Markdown.

The report is intentionally source-first:

    function -> optional loop -> source statement/expression -> source -> instruction PC

The input `.hotpc` remains the machine-oriented interface for second-stage
breakpoint registration.  This script only generates a human-readable
`*.resolved.md` report for optimization review.
"""

from __future__ import annotations

import argparse
import json
import re
import shlex
import shutil
import subprocess
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple


SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".C", ".h", ".hh", ".hpp", ".hxx"}
LOC_RE = re.compile(r"^(?P<file>.*?):(?P<line>\d+)(?::(?P<column>\d+))?(?:\s.*)?$")
DISASM_RE = re.compile(
    r"^\s*(?P<addr>[0-9a-fA-F]+):\s+"
    r"(?:(?:[0-9a-fA-F]{2,8})\s+)+"
    r"(?P<mnemonic>[A-Za-z0-9_.]+)\s*(?P<operands>.*)$"
)


@dataclass(frozen=True)
class HotspotEntry:
    tid: int
    rank: int
    sample_count: int
    module_id: int
    pc_offset: int
    path: str
    pareto_front: int = 0
    candidate_score: int = 0
    candidate_metric: str = ""
    avg_mem_latency: float = 0.0
    lat_total_sum: int = 0
    lat_issue_sum: int = 0
    lat_xlat_sum: int = 0
    lat_exec_sum: int = 0
    l1d_refill_count: int = 0
    llc_miss_count: int = 0
    tlb_walk_count: int = 0
    remote_access_count: int = 0


@dataclass
class HotspotPc:
    path: str
    module_id: int
    pc_offset: int
    entries: List[HotspotEntry]
    sample_count_sum: int
    candidate_score_sum: int
    avg_mem_latency_weighted: float
    lat_total_sum: int
    lat_issue_sum: int
    lat_xlat_sum: int
    lat_exec_sum: int
    l1d_refill_count: int
    llc_miss_count: int
    tlb_walk_count: int
    remote_access_count: int
    pareto_pc_count: int


@dataclass(frozen=True)
class Frame:
    function: str
    file: str
    line: int
    column: int
    raw_location: str

    def source_label(self, source_root: Optional[Path]) -> str:
        if not self.file or self.line <= 0:
            return "unresolved"
        path = display_path(self.file, source_root)
        if self.column > 0:
            return f"{path}:{self.line}:{self.column}"
        return f"{path}:{self.line}"


@dataclass(frozen=True)
class InstructionInfo:
    text: str
    mnemonic: str
    operands: str


@dataclass(frozen=True)
class LoopRegion:
    kind: str
    file: str
    start_line: int
    start_column: int
    end_line: int
    end_column: int
    depth: int

    def contains(self, file: str, line: int, column: int) -> bool:
        if normalize_path(file) != normalize_path(self.file) or line <= 0:
            return False
        col = column if column > 0 else 1
        start = (self.start_line, self.start_column if self.start_column > 0 else 1)
        end = (self.end_line, self.end_column if self.end_column > 0 else 1_000_000)
        return start <= (line, col) <= end

    def label(self, source_root: Optional[Path]) -> str:
        return f"loop at {display_path(self.file, source_root)}:{self.start_line} ({self.kind})"


@dataclass(frozen=True)
class StatementRegion:
    kind: str
    file: str
    start_line: int
    start_column: int
    end_line: int
    end_column: int
    text: str

    def contains(self, file: str, line: int, column: int) -> bool:
        if normalize_path(file) != normalize_path(self.file) or line <= 0:
            return False
        col = column if column > 0 else 1
        start = (self.start_line, self.start_column if self.start_column > 0 else 1)
        end = (self.end_line, self.end_column if self.end_column > 0 else 1_000_000)
        return start <= (line, col) <= end

    def label(self, source_root: Optional[Path]) -> str:
        if self.text:
            return f"statement: `{self.text}`"
        loc = f"{display_path(self.file, source_root)}:{self.start_line}"
        return f"statement at {loc}"


@dataclass
class ResolvedHotspot:
    pc: HotspotPc
    frames: List[Frame]
    instruction: Optional[InstructionInfo]
    function: str
    source_frame: Optional[Frame]
    loop: Optional[LoopRegion]
    statement: Optional[StatementRegion]
    unresolved_reason: str = ""


@dataclass
class Metrics:
    sample_count_sum: int = 0
    candidate_score_sum: int = 0
    latency_weighted_num: float = 0.0
    latency_weight: int = 0
    lat_total_sum: int = 0
    lat_issue_sum: int = 0
    lat_xlat_sum: int = 0
    lat_exec_sum: int = 0
    l1d_refill_count: int = 0
    llc_miss_count: int = 0
    tlb_walk_count: int = 0
    remote_access_count: int = 0
    pareto_pc_count: int = 0
    pc_count: int = 0

    def add(self, pc: HotspotPc) -> None:
        self.sample_count_sum += pc.sample_count_sum
        self.candidate_score_sum += pc.candidate_score_sum
        self.latency_weighted_num += pc.avg_mem_latency_weighted * pc.sample_count_sum
        self.latency_weight += pc.sample_count_sum
        self.lat_total_sum += pc.lat_total_sum
        self.lat_issue_sum += pc.lat_issue_sum
        self.lat_xlat_sum += pc.lat_xlat_sum
        self.lat_exec_sum += pc.lat_exec_sum
        self.l1d_refill_count += pc.l1d_refill_count
        self.llc_miss_count += pc.llc_miss_count
        self.tlb_walk_count += pc.tlb_walk_count
        self.remote_access_count += pc.remote_access_count
        self.pareto_pc_count += pc.pareto_pc_count
        self.pc_count += 1

    @property
    def avg_mem_latency_weighted(self) -> float:
        return self.latency_weighted_num / self.latency_weight if self.latency_weight else 0.0


def normalize_path(path: str | Path) -> str:
    if not path:
        return ""
    try:
        return str(Path(path).expanduser().resolve())
    except OSError:
        return str(Path(path).expanduser())


def display_path(path: str | Path, source_root: Optional[Path]) -> str:
    if not path:
        return ""
    p = Path(path)
    if source_root:
        try:
            return str(p.resolve().relative_to(source_root.resolve()))
        except Exception:
            pass
    return str(p)


def path_under_root(path: str, source_root: Optional[Path]) -> bool:
    if source_root is None or not path:
        return False
    try:
        Path(path).resolve().relative_to(source_root.resolve())
        return True
    except Exception:
        return False


def parse_location(loc: str) -> Tuple[str, int, int]:
    loc = loc.strip()
    if loc in ("", "??:?", "??:0"):
        return "", 0, 0
    match = LOC_RE.match(loc)
    if not match:
        return loc, 0, 0
    return match.group("file"), int(match.group("line")), int(match.group("column") or 0)


def run_tool(args: Sequence[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("hotpc_pos", nargs="?", help="Path to a .hotpc manifest")
    parser.add_argument("--hotpc", dest="hotpc_opt", help="Path to a .hotpc manifest")
    parser.add_argument("--info", help="Path to the matching .info file")
    parser.add_argument("--source-root", type=Path, help="Root used for source path display/filtering")
    parser.add_argument("--compile-commands", type=Path, help="compile_commands.json for libclang AST resolution")
    parser.add_argument("--output", "-o", type=Path, help="Output Markdown path, defaults to <hotpc stem>.resolved.md")
    parser.add_argument(
        "--filtered-hotpc",
        type=Path,
        help="Filtered .hotpc for targeted_rd, defaults to <hotpc stem>.filtered.hotpc",
    )
    parser.add_argument("--top", type=int, default=50, help="Maximum children to show at each report level")
    args = parser.parse_args(argv)
    args.hotpc = args.hotpc_opt or args.hotpc_pos
    if not args.hotpc:
        parser.error("a .hotpc path is required, either positional or via --hotpc")
    return args


def parse_info(path: Optional[Path]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if path is None or not path.exists():
        return out
    with path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if line and "=" in line:
                key, value = line.split("=", 1)
                out[key] = value
    return out


def parse_hotpc(path: Path) -> Tuple[Dict[str, str], List[HotspotEntry]]:
    metadata: Dict[str, str] = {}
    entries: List[HotspotEntry] = []
    with path.open(encoding="utf-8", errors="replace") as fh:
        for raw_line in fh:
            line = raw_line.rstrip("\n")
            if not line:
                continue
            if line.startswith("hotspot="):
                parts = line.split("=", 1)[1].split("\t")
                if len(parts) < 6:
                    raise SystemExit(f"malformed hotspot entry: {line}")
                extra = parts[6:]
                entries.append(
                    HotspotEntry(
                        tid=int(parts[0], 10),
                        rank=int(parts[1], 10),
                        sample_count=int(parts[2], 10),
                        module_id=int(parts[3], 10),
                        pc_offset=int(parts[4], 16),
                        path=parts[5],
                        pareto_front=int(extra[0], 10) if len(extra) > 0 and extra[0] else 0,
                        candidate_score=int(extra[1], 10) if len(extra) > 1 and extra[1] else int(parts[2], 10),
                        candidate_metric=extra[2] if len(extra) > 2 else "sample_count",
                        avg_mem_latency=float(extra[3]) if len(extra) > 3 and extra[3] else 0.0,
                        lat_total_sum=int(extra[4], 10) if len(extra) > 4 and extra[4] else 0,
                        lat_issue_sum=int(extra[5], 10) if len(extra) > 5 and extra[5] else 0,
                        lat_xlat_sum=int(extra[6], 10) if len(extra) > 6 and extra[6] else 0,
                        lat_exec_sum=int(extra[7], 10) if len(extra) > 7 and extra[7] else 0,
                        l1d_refill_count=int(extra[8], 10) if len(extra) > 8 and extra[8] else 0,
                        llc_miss_count=int(extra[9], 10) if len(extra) > 9 and extra[9] else 0,
                        tlb_walk_count=int(extra[10], 10) if len(extra) > 10 and extra[10] else 0,
                        remote_access_count=int(extra[11], 10) if len(extra) > 11 and extra[11] else 0,
                    )
                )
            elif "=" in line:
                key, value = line.split("=", 1)
                metadata[key] = value
    return metadata, entries


def aggregate_hotspots(entries: Iterable[HotspotEntry]) -> List[HotspotPc]:
    grouped: Dict[Tuple[str, int, int], List[HotspotEntry]] = defaultdict(list)
    for entry in entries:
        grouped[(entry.path, entry.module_id, entry.pc_offset)].append(entry)

    out: List[HotspotPc] = []
    for (path, module_id, pc_offset), group in grouped.items():
        sample_sum = sum(entry.sample_count for entry in group)
        score_sum = sum(entry.candidate_score or entry.sample_count for entry in group)
        out.append(
            HotspotPc(
                path=path,
                module_id=module_id,
                pc_offset=pc_offset,
                entries=sorted(group, key=lambda e: (e.tid, e.rank)),
                sample_count_sum=sample_sum,
                candidate_score_sum=score_sum,
                avg_mem_latency_weighted=(
                    sum(entry.avg_mem_latency * entry.sample_count for entry in group) / sample_sum
                    if sample_sum
                    else 0.0
                ),
                lat_total_sum=sum(entry.lat_total_sum for entry in group),
                lat_issue_sum=sum(entry.lat_issue_sum for entry in group),
                lat_xlat_sum=sum(entry.lat_xlat_sum for entry in group),
                lat_exec_sum=sum(entry.lat_exec_sum for entry in group),
                l1d_refill_count=sum(entry.l1d_refill_count for entry in group),
                llc_miss_count=sum(entry.llc_miss_count for entry in group),
                tlb_walk_count=sum(entry.tlb_walk_count for entry in group),
                remote_access_count=sum(entry.remote_access_count for entry in group),
                pareto_pc_count=1 if any(entry.pareto_front for entry in group) else 0,
            )
        )
    out.sort(key=lambda pc: (-pc.lat_exec_sum, -pc.candidate_score_sum, -pc.sample_count_sum, pc.path, pc.pc_offset))
    return out


def frames_from_llvm_symbolizer(binary: Path, offsets: Sequence[int]) -> Dict[int, List[Frame]]:
    tool = shutil.which("llvm-symbolizer")
    if not tool or not offsets:
        return {}
    proc = run_tool([tool, "--inlining", "--demangle", "-e", str(binary), *[hex(o) for o in offsets]])
    if proc.returncode != 0:
        return {}
    groups: List[List[str]] = []
    cur: List[str] = []
    for line in proc.stdout.splitlines():
        if not line.strip():
            if cur:
                groups.append(cur)
                cur = []
            continue
        cur.append(line.rstrip())
    if cur:
        groups.append(cur)

    out: Dict[int, List[Frame]] = {}
    for offset, group in zip(offsets, groups):
        frames: List[Frame] = []
        for i in range(0, len(group), 2):
            function = group[i].strip() if i < len(group) else "??"
            loc = group[i + 1].strip() if i + 1 < len(group) else "??:?"
            file, line, column = parse_location(loc)
            frames.append(Frame(function, normalize_path(file), line, column, loc))
        out[offset] = frames
    return out


def frames_from_addr2line(binary: Path, offsets: Sequence[int]) -> Dict[int, List[Frame]]:
    if not offsets:
        return {}
    proc = run_tool(["addr2line", "-f", "-C", "-i", "-e", str(binary), *[hex(o) for o in offsets]])
    if proc.returncode != 0:
        return {}
    lines = proc.stdout.splitlines()
    out: Dict[int, List[Frame]] = {}
    idx = 0
    for offset in offsets:
        frames: List[Frame] = []
        while idx + 1 < len(lines):
            function = lines[idx].strip()
            loc = lines[idx + 1].strip()
            idx += 2
            file, line, column = parse_location(loc)
            frames.append(Frame(function, normalize_path(file), line, column, loc))
            # addr2line prints all inlined frames for one address together, but
            # no separator.  In this repository's use cases one or two frames
            # are enough; llvm-symbolizer is preferred for exact grouping.
            break
        out[offset] = frames
    return out


def symbolize_module(binary: Path, offsets: Sequence[int]) -> Dict[int, List[Frame]]:
    frames = frames_from_llvm_symbolizer(binary, offsets)
    missing = [offset for offset in offsets if offset not in frames or not frames[offset]]
    if missing:
        fallback = frames_from_addr2line(binary, missing)
        frames.update(fallback)
    return frames


def disassemble_instruction(binary: Path, offset: int) -> Optional[InstructionInfo]:
    if not binary.exists():
        return None
    proc = run_tool(
        [
            "objdump",
            "-d",
            f"--start-address=0x{offset:x}",
            f"--stop-address=0x{offset + 4:x}",
            str(binary),
        ]
    )
    if proc.returncode != 0:
        return None
    for line in proc.stdout.splitlines():
        match = DISASM_RE.match(line)
        if not match:
            continue
        try:
            addr = int(match.group("addr"), 16)
        except ValueError:
            continue
        if addr != offset:
            continue
        mnemonic = match.group("mnemonic").lower()
        operands = re.sub(r"\s+", " ", match.group("operands").strip())
        text = f"{mnemonic} {operands}".strip()
        return InstructionInfo(text=text, mnemonic=mnemonic, operands=operands)
    return None


def is_callee_saved_register(reg: str) -> bool:
    reg = reg.lower()
    match = re.fullmatch(r"[xw](\d+)", reg)
    if match:
        num = int(match.group(1))
        return 19 <= num <= 30
    match = re.fullmatch(r"[dqv](\d+)", reg)
    if match:
        num = int(match.group(1))
        return 8 <= num <= 15
    return reg in {"fp", "lr"}


def stack_register_operands(instruction: InstructionInfo) -> List[str]:
    before_memory = instruction.operands.split("[", 1)[0]
    return re.findall(r"\b(?:[xw]\d+|[dqv]\d+|fp|lr)\b", before_memory.lower())


def prologue_epilogue_reason(instruction: Optional[InstructionInfo]) -> str:
    """Classify compiler stack-frame save/restore instructions."""
    if instruction is None:
        return ""
    if instruction.mnemonic not in {"stp", "ldp", "str", "ldr", "stur", "ldur"}:
        return ""
    if not re.search(r"\[sp(?:,|\])", instruction.operands.lower()):
        return ""
    regs = stack_register_operands(instruction)
    if not regs or not all(is_callee_saved_register(reg) for reg in regs):
        return ""
    if instruction.mnemonic.startswith("st"):
        return "function_prologue_callee_saved_spill"
    return "function_epilogue_callee_saved_restore"


def import_clang_cindex():
    try:
        from clang import cindex  # type: ignore
    except ImportError as exc:
        raise SystemExit("libclang source attribution requires Python clang bindings") from exc
    for candidate in (
        "/usr/lib/llvm-14/lib/libclang.so.1",
        "/usr/lib/llvm-14/lib/libclang-14.so.1",
        "/usr/lib/aarch64-linux-gnu/libclang-14.so.1",
    ):
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
        return []
    with path.open(encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, list):
        raise SystemExit("compile_commands.json must be a JSON array")
    return data


def command_arguments(entry: dict) -> List[str]:
    if isinstance(entry.get("arguments"), list):
        return list(entry["arguments"])
    if entry.get("command"):
        return shlex.split(entry["command"])
    return []


def gcc_include_dir() -> Optional[str]:
    gcc = shutil.which("g++") or shutil.which("gcc")
    if not gcc:
        return None
    proc = run_tool([gcc, "-print-file-name=include"])
    path = proc.stdout.strip() if proc.returncode == 0 else ""
    return path if path and Path(path).is_dir() else None


def filtered_clang_args(entry: dict, source_file: str) -> List[str]:
    raw = command_arguments(entry)
    if raw:
        raw = raw[1:]
    directory = Path(entry.get("directory", "."))
    out: List[str] = []
    skip_next = False
    source_name = Path(source_file).name
    for arg in raw:
        if skip_next:
            skip_next = False
            continue
        if arg in {"-o", "-MF", "-MT", "-MQ", "-include-pch"}:
            skip_next = True
            continue
        arg_path = Path(arg)
        if arg == "-c" or (
            not arg.startswith("-")
            and arg_path.name == source_name
            and arg_path.suffix in {".c", ".cc", ".cpp", ".cxx", ".C"}
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


def cursor_kind_name(kind) -> str:
    text = str(kind)
    return text.split(".")[-1] if "." in text else text


def loop_kind(cindex, kind) -> Optional[str]:
    if kind == cindex.CursorKind.FOR_STMT:
        return "for"
    if kind == cindex.CursorKind.WHILE_STMT:
        return "while"
    if kind == cindex.CursorKind.DO_STMT:
        return "do"
    if hasattr(cindex.CursorKind, "CXX_FOR_RANGE_STMT") and kind == cindex.CursorKind.CXX_FOR_RANGE_STMT:
        return "range_for"
    return None


def is_statement_kind(cindex, kind) -> bool:
    wanted_names = {
        "DECL_STMT",
        "BINARY_OPERATOR",
        "COMPOUND_ASSIGNMENT_OPERATOR",
        "CALL_EXPR",
        "ARRAY_SUBSCRIPT_EXPR",
        "RETURN_STMT",
        "IF_STMT",
        "FOR_STMT",
        "WHILE_STMT",
        "DO_STMT",
        "CXX_FOR_RANGE_STMT",
        "UNARY_OPERATOR",
        "ASM_STMT",
    }
    return cursor_kind_name(kind) in wanted_names


def read_source_range(path: str, start_line: int, start_col: int, end_line: int, end_col: int) -> str:
    try:
        lines = Path(path).read_text(encoding="utf-8", errors="replace").split("\n")
    except OSError:
        return ""
    if start_line <= 0 or end_line <= 0 or start_line > len(lines):
        return ""
    end_line = min(end_line, len(lines))
    if start_line == end_line:
        text = lines[start_line - 1]
        start = max(start_col - 1, 0)
        end = max(end_col - 1, start)
        snippet = text[start:end].strip() or text.strip()
    else:
        snippet = " ".join(line.strip() for line in lines[start_line - 1 : end_line])
    snippet = re.sub(r"\s+", " ", snippet).strip()
    return snippet[:180] + ("..." if len(snippet) > 180 else "")


def source_statement_fragment(frame: Frame) -> str:
    """Return a readable source statement fragment around a debug line column."""
    try:
        lines = Path(frame.file).read_text(encoding="utf-8", errors="replace").split("\n")
    except OSError:
        return ""
    if frame.line <= 0 or frame.line > len(lines):
        return ""
    line = lines[frame.line - 1]
    stripped = line.strip()
    if not stripped or stripped in ("{", "}", "};"):
        return ""
    col = min(max(frame.column - 1, 0), max(len(line) - 1, 0))
    if_fragment = split_single_line_if_fragment(line, col)
    if if_fragment:
        return if_fragment
    starts = [line.rfind(token, 0, col + 1) for token in (";", "{", "}")]
    start = max(starts)
    start = start + 1 if start >= 0 else 0
    ends = [idx for idx in (line.find(";", col), line.find("{", col), line.find("}", col)) if idx >= 0]
    end = min(ends) + 1 if ends else len(line)
    snippet = line[start:end].strip()
    if snippet in ("", "{", "}", "};"):
        return ""
    snippet = re.sub(r"\s+", " ", snippet).strip()
    return snippet[:180] + ("..." if len(snippet) > 180 else "")


def split_single_line_if_fragment(line: str, col: int) -> str:
    """Split `if (cond) stmt;` lines so one PC maps to condition or body."""
    match = re.search(r"\bif\s*\(", line)
    if not match:
        return ""
    open_idx = line.find("(", match.start())
    if open_idx < 0:
        return ""
    depth = 0
    close_idx = -1
    for idx in range(open_idx, len(line)):
        ch = line[idx]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                close_idx = idx
                break
    if close_idx < 0:
        return ""
    if col <= close_idx:
        condition = line[open_idx + 1 : close_idx].strip()
        return f"if condition: {re.sub(r'\\s+', ' ', condition)}" if condition else ""
    body = line[close_idx + 1 :].strip()
    return re.sub(r"\s+", " ", body)[:180] if body and body not in ("{", "}") else ""


def extract_ast_regions(
    source_files: Iterable[str],
    compile_commands: Optional[Path],
    source_root: Optional[Path],
) -> Tuple[List[LoopRegion], List[StatementRegion], List[str]]:
    if compile_commands is None:
        return [], [], ["compile_commands not provided; loop/statement attribution disabled"]
    cindex = import_clang_cindex()
    entries = load_compile_commands(compile_commands)
    index = cindex.Index.create()
    loops: List[LoopRegion] = []
    statements: List[StatementRegion] = []
    diagnostics: List[str] = []
    wanted_sources = {normalize_path(s) for s in source_files if s and Path(s).exists()}
    source_root_norm = normalize_path(source_root) if source_root else ""
    seen_tus = set()

    for source in sorted(wanted_sources):
        entry = compile_entry_for_file(entries, source)
        if entry is None:
            diagnostics.append(f"no compile command for {source}")
            continue
        tu_file = Path(entry.get("file", source))
        if not tu_file.is_absolute():
            tu_file = Path(entry.get("directory", ".")) / tu_file
        tu_file_norm = normalize_path(tu_file)
        if tu_file_norm in seen_tus:
            continue
        seen_tus.add(tu_file_norm)
        try:
            tu = index.parse(tu_file_norm, args=filtered_clang_args(entry, tu_file_norm), options=0)
        except Exception as exc:
            diagnostics.append(f"failed to parse {tu_file_norm}: {exc}")
            continue
        diagnostics.extend(str(diag) for diag in tu.diagnostics)

        def in_scope(file_norm: str) -> bool:
            if file_norm in wanted_sources:
                return True
            return bool(source_root_norm and file_norm.startswith(source_root_norm + "/"))

        def visit(cursor, depth: int) -> None:
            start = cursor.extent.start
            end = cursor.extent.end
            if start.file and end.file:
                file_norm = normalize_path(str(start.file))
                if in_scope(file_norm):
                    lk = loop_kind(cindex, cursor.kind)
                    if lk:
                        loops.append(
                            LoopRegion(
                                kind=lk,
                                file=file_norm,
                                start_line=start.line,
                                start_column=start.column,
                                end_line=end.line,
                                end_column=end.column,
                                depth=depth,
                            )
                        )
                    if is_statement_kind(cindex, cursor.kind):
                        statements.append(
                            StatementRegion(
                                kind=cursor_kind_name(cursor.kind),
                                file=file_norm,
                                start_line=start.line,
                                start_column=start.column,
                                end_line=end.line,
                                end_column=end.column,
                                text=read_source_range(file_norm, start.line, start.column, end.line, end.column),
                            )
                        )
            for child in cursor.get_children():
                visit(child, depth + 1)

        visit(tu.cursor, 0)
    return loops, statements, diagnostics


def innermost_loop(frame: Frame, loops_by_file: Dict[str, List[LoopRegion]]) -> Optional[LoopRegion]:
    candidates = [loop for loop in loops_by_file.get(normalize_path(frame.file), []) if loop.contains(frame.file, frame.line, frame.column)]
    if not candidates:
        return None
    return max(candidates, key=lambda loop: (loop.depth, -(loop.end_line - loop.start_line), loop.start_line))


def nearest_statement(frame: Frame, stmts_by_file: Dict[str, List[StatementRegion]]) -> Optional[StatementRegion]:
    candidates = [stmt for stmt in stmts_by_file.get(normalize_path(frame.file), []) if stmt.contains(frame.file, frame.line, frame.column)]
    if not candidates:
        return None
    return min(
        candidates,
        key=lambda stmt: (
            stmt.end_line - stmt.start_line,
            stmt.end_column - stmt.start_column,
            -len(stmt.kind),
        ),
    )


def choose_source_frame(frames: Sequence[Frame], source_root: Optional[Path]) -> Optional[Frame]:
    valid = [f for f in frames if f.file and f.line > 0 and Path(f.file).exists()]
    if source_root:
        for frame in valid:
            if path_under_root(frame.file, source_root):
                return frame
    return valid[0] if valid else None


def resolve_hotspots(
    pcs: Sequence[HotspotPc],
    source_root: Optional[Path],
    compile_commands: Optional[Path],
) -> Tuple[List[ResolvedHotspot], List[str]]:
    by_module: Dict[str, List[HotspotPc]] = defaultdict(list)
    for pc in pcs:
        by_module[pc.path].append(pc)

    frames_by_key: Dict[Tuple[str, int], List[Frame]] = {}
    instructions_by_key: Dict[Tuple[str, int], Optional[InstructionInfo]] = {}
    for module, module_pcs in by_module.items():
        binary = Path(module)
        if not binary.exists():
            for pc in module_pcs:
                frames_by_key[(module, pc.pc_offset)] = []
                instructions_by_key[(module, pc.pc_offset)] = None
            continue
        offsets = [pc.pc_offset for pc in module_pcs]
        symbolized = symbolize_module(binary, offsets)
        for pc in module_pcs:
            frames_by_key[(module, pc.pc_offset)] = symbolized.get(pc.pc_offset, [])
            instructions_by_key[(module, pc.pc_offset)] = disassemble_instruction(binary, pc.pc_offset)

    source_files = set()
    for frames in frames_by_key.values():
        for frame in frames:
            if not (frame.file and frame.line > 0 and Path(frame.file).exists()):
                continue
            if source_root and not path_under_root(frame.file, source_root):
                continue
            source_files.add(frame.file)
    loops, statements, diagnostics = extract_ast_regions(source_files, compile_commands, source_root)
    loops_by_file: Dict[str, List[LoopRegion]] = defaultdict(list)
    statements_by_file: Dict[str, List[StatementRegion]] = defaultdict(list)
    for loop in loops:
        loops_by_file[normalize_path(loop.file)].append(loop)
    for stmt in statements:
        statements_by_file[normalize_path(stmt.file)].append(stmt)

    resolved: List[ResolvedHotspot] = []
    for pc in pcs:
        frames = frames_by_key.get((pc.path, pc.pc_offset), [])
        instruction = instructions_by_key.get((pc.path, pc.pc_offset))
        usable = [f for f in frames if f.function and f.function != "??"]
        source_frame = choose_source_frame(frames, source_root)
        function = (
            source_frame.function
            if source_frame and source_frame.function and source_frame.function != "??"
            else (usable[0].function if usable else f"{Path(pc.path).name}+0x{pc.pc_offset:x}")
        )
        loop = innermost_loop(source_frame, loops_by_file) if source_frame else None
        statement = nearest_statement(source_frame, statements_by_file) if source_frame else None
        statement_fragment = source_statement_fragment(source_frame) if source_frame else ""
        reason = ""
        if source_frame is None:
            reason = "source_unresolved"
        elif statement is None:
            reason = "statement_unresolved"
        filtered_reason = prologue_epilogue_reason(instruction)
        if not filtered_reason and source_frame is None:
            filtered_reason = "source_unresolved"
        if not filtered_reason and not statement_fragment:
            filtered_reason = "non_source_statement"
        if filtered_reason:
            source = source_frame.source_label(source_root) if source_frame else "unresolved"
            instruction_text = instruction.text if instruction else "unknown"
            diagnostics.append(
                "filtered "
                f"{filtered_reason}: pc=0x{pc.pc_offset:x} "
                f"samples={pc.sample_count_sum} source={source} instruction={instruction_text}"
            )
            continue
        resolved.append(ResolvedHotspot(pc, frames, instruction, function, source_frame, loop, statement, reason))
    return resolved, diagnostics


def metrics_for(items: Sequence[ResolvedHotspot]) -> Metrics:
    metrics = Metrics()
    for item in items:
        metrics.add(item.pc)
    return metrics


def metrics_lines(metrics: Metrics) -> List[str]:
    return [
        f"- sample_count_sum: {metrics.sample_count_sum}",
        f"- candidate_score_sum: {metrics.candidate_score_sum}",
        f"- avg_mem_latency_weighted: {metrics.avg_mem_latency_weighted:.6g}",
        f"- lat_total_sum: {metrics.lat_total_sum}",
        f"- lat_issue_sum: {metrics.lat_issue_sum}",
        f"- lat_xlat_sum: {metrics.lat_xlat_sum}",
        f"- lat_exec_sum: {metrics.lat_exec_sum}",
        f"- l1d_refill_count: {metrics.l1d_refill_count}",
        f"- llc_miss_count: {metrics.llc_miss_count}",
        f"- tlb_walk_count: {metrics.tlb_walk_count}",
        f"- remote_access_count: {metrics.remote_access_count}",
        f"- pareto_pc_count: {metrics.pareto_pc_count}",
        f"- pc_count: {metrics.pc_count}",
    ]


def sort_items(items: Iterable[ResolvedHotspot]) -> List[ResolvedHotspot]:
    return sorted(
        items,
        key=lambda item: (
            -item.pc.lat_exec_sum,
            -item.pc.candidate_score_sum,
            -item.pc.sample_count_sum,
            item.pc.path,
            item.pc.pc_offset,
        ),
    )


def group_key_loop(item: ResolvedHotspot, source_root: Optional[Path]) -> str:
    return item.loop.label(source_root) if item.loop else "(no loop)"


def group_key_statement(item: ResolvedHotspot, source_root: Optional[Path]) -> str:
    if item.source_frame:
        fragment = source_statement_fragment(item.source_frame)
        if fragment:
            return f"statement: `{fragment}`"
        return "(no expression statement on resolved line)"
    if item.statement:
        return item.statement.label(source_root)
    if item.unresolved_reason:
        return f"({item.unresolved_reason})"
    return "(statement unresolved)"


def group_key_source(item: ResolvedHotspot, source_root: Optional[Path]) -> str:
    return item.source_frame.source_label(source_root) if item.source_frame else "unresolved"


def tree_indent(depth: int, is_last: bool) -> str:
    if depth <= 0:
        return ""
    return "    " * (depth - 1) + ("└── " if is_last else "├── ")


def write_tree_line(out, depth: int, is_last: bool, label: str) -> None:
    out.write(f"{tree_indent(depth, is_last)}{label}\n")


def pc_label(item: ResolvedHotspot) -> str:
    rank = item.pc.entries[0].rank
    return f"[P{rank:02d}] pc=0x{item.pc.pc_offset:x}, samples={item.pc.sample_count_sum}"


def write_attribution_tree(
    out,
    resolved: Sequence[ResolvedHotspot],
    source_root: Optional[Path],
    top: int,
) -> None:
    by_function: Dict[str, List[ResolvedHotspot]] = defaultdict(list)
    for item in resolved:
        by_function[item.function].append(item)

    out.write("## Hotspot Attribution Tree\n\n")
    out.write("```text\n")
    out.write("<program root>\n")
    sorted_functions = sorted(
        by_function.items(),
        key=lambda kv: (-metrics_for(kv[1]).lat_exec_sum, -metrics_for(kv[1]).sample_count_sum, kv[0]),
    )[:top]
    for fn_idx, (function, fn_items) in enumerate(sorted_functions):
        fn_last = fn_idx == len(sorted_functions) - 1
        write_tree_line(out, 1, fn_last, function)
        by_loop: Dict[str, List[ResolvedHotspot]] = defaultdict(list)
        for item in fn_items:
            by_loop[group_key_loop(item, source_root)].append(item)
        sorted_loops = sorted(
            by_loop.items(),
            key=lambda kv: (-metrics_for(kv[1]).lat_exec_sum, -metrics_for(kv[1]).sample_count_sum, kv[0]),
        )[:top]
        for loop_idx, (loop_label, loop_items) in enumerate(sorted_loops):
            loop_last = loop_idx == len(sorted_loops) - 1
            if loop_label != "(no loop)":
                write_tree_line(out, 2, loop_last, loop_label)
                stmt_depth = 3
                source_depth = 4
                pc_depth = 5
            else:
                stmt_depth = 2
                source_depth = 3
                pc_depth = 4

            by_stmt: Dict[str, List[ResolvedHotspot]] = defaultdict(list)
            for item in loop_items:
                by_stmt[group_key_statement(item, source_root)].append(item)
            sorted_stmts = sorted(
                by_stmt.items(),
                key=lambda kv: (-metrics_for(kv[1]).lat_exec_sum, -metrics_for(kv[1]).sample_count_sum, kv[0]),
            )[:top]
            for stmt_idx, (stmt_label, stmt_items) in enumerate(sorted_stmts):
                stmt_last = stmt_idx == len(sorted_stmts) - 1
                write_tree_line(out, stmt_depth, stmt_last, stmt_label)
                by_source: Dict[str, List[ResolvedHotspot]] = defaultdict(list)
                for item in stmt_items:
                    by_source[group_key_source(item, source_root)].append(item)
                sorted_sources = sorted(by_source.items(), key=lambda kv: kv[0])[:top]
                for src_idx, (source_label, source_items) in enumerate(sorted_sources):
                    src_last = src_idx == len(sorted_sources) - 1
                    write_tree_line(out, source_depth, src_last, source_label)
                    pcs = sort_items(source_items)
                    for pc_idx, item in enumerate(pcs):
                        write_tree_line(out, pc_depth, pc_idx == len(pcs) - 1, pc_label(item))
    out.write("```\n\n")


def write_metrics_table(out, resolved: Sequence[ResolvedHotspot], source_root: Optional[Path]) -> None:
    out.write("## Instruction Metrics\n\n")
    out.write(
        "| id | rank | pc_offset | module | function | source | sample_count | avg_mem_latency | "
        "lat_exec_sum | pareto_front | l1d_refill | llc_miss | tlb_walk | remote_access |\n"
    )
    out.write("|---|---:|---:|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|\n")
    for item in sort_items(resolved):
        pc = item.pc
        rank = pc.entries[0].rank
        source = group_key_source(item, source_root)
        out.write(
            f"| P{rank:02d} | {rank} | 0x{pc.pc_offset:x} | {Path(pc.path).name} | "
            f"{item.function} | {source} | {pc.sample_count_sum} | "
            f"{pc.avg_mem_latency_weighted:.6g} | {pc.lat_exec_sum} | {pc.pareto_pc_count} | "
            f"{pc.l1d_refill_count} | {pc.llc_miss_count} | {pc.tlb_walk_count} | {pc.remote_access_count} |\n"
        )
    out.write("\n")

    out.write("## Inline Chains And Unresolved Notes\n\n")
    for item in sort_items(resolved):
        rank = item.pc.entries[0].rank
        if item.frames:
            chain = " -> ".join(frame.source_label(source_root) for frame in item.frames)
            out.write(f"- P{rank:02d} inline_chain: `{chain}`\n")
        if item.unresolved_reason:
            out.write(f"- P{rank:02d} unresolved: `{item.unresolved_reason}`\n")
    out.write("\n")


def write_report(
    path: Path,
    hotpc_path: Path,
    info_path: Optional[Path],
    filtered_hotpc_path: Path,
    resolved: Sequence[ResolvedHotspot],
    diagnostics: Sequence[str],
    source_root: Optional[Path],
    top: int,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as out:
        out.write("# Hotspot Source Attribution Report\n\n")
        out.write(f"- hotpc: `{hotpc_path}`\n")
        out.write(f"- filtered_hotpc: `{filtered_hotpc_path}`\n")
        if info_path:
            out.write(f"- info: `{info_path}`\n")
        if source_root:
            out.write(f"- source_root: `{source_root}`\n")
        out.write(f"- unique_instruction_pcs: {len(resolved)}\n\n")
        if diagnostics:
            out.write("## Attribution Diagnostics\n\n")
            for diag in diagnostics[:30]:
                out.write(f"- `{diag}`\n")
            out.write("\n")
        write_attribution_tree(out, resolved, source_root, top)
        write_metrics_table(out, resolved, source_root)


def filtered_hotspot_keys(resolved: Sequence[ResolvedHotspot]) -> set[Tuple[str, int, int]]:
    return {(item.pc.path, item.pc.module_id, item.pc.pc_offset) for item in resolved}


def hotspot_entry_line(entry: HotspotEntry, rank: int) -> str:
    return (
        "hotspot="
        f"{entry.tid}\t"
        f"{rank}\t"
        f"{entry.sample_count}\t"
        f"{entry.module_id}\t"
        f"0x{entry.pc_offset:x}\t"
        f"{entry.path}\t"
        f"{entry.pareto_front}\t"
        f"{entry.candidate_score}\t"
        f"{entry.candidate_metric}\t"
        f"{entry.avg_mem_latency:.6g}\t"
        f"{entry.lat_total_sum}\t"
        f"{entry.lat_issue_sum}\t"
        f"{entry.lat_xlat_sum}\t"
        f"{entry.lat_exec_sum}\t"
        f"{entry.l1d_refill_count}\t"
        f"{entry.llc_miss_count}\t"
        f"{entry.tlb_walk_count}\t"
        f"{entry.remote_access_count}"
    )


def write_filtered_hotpc(
    path: Path,
    original_hotpc: Path,
    metadata: Dict[str, str],
    entries: Sequence[HotspotEntry],
    resolved: Sequence[ResolvedHotspot],
) -> None:
    keep = filtered_hotspot_keys(resolved)
    filtered = [
        entry
        for entry in entries
        if (entry.path, entry.module_id, entry.pc_offset) in keep
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    meta = dict(metadata)
    meta["hotspot_filter"] = "source_statement_valid"
    meta["hotspot_filter_input"] = str(original_hotpc)
    meta["hotspot_filter_removed_count"] = str(len(entries) - len(filtered))
    meta["hotspot_count"] = str(len(filtered))
    meta["hotspot_fields"] = (
        "tid,rank,sample_count,module_id,pc_offset,path,pareto_front,candidate_score,"
        "candidate_metric,avg_mem_latency,lat_total_sum,lat_issue_sum,lat_xlat_sum,"
        "lat_exec_sum,l1d_refill_count,llc_miss_count,tlb_walk_count,remote_access_count"
    )
    with path.open("w", encoding="utf-8") as out:
        for key in sorted(meta):
            out.write(f"{key}={meta[key]}\n")
        by_tid: Dict[int, List[HotspotEntry]] = defaultdict(list)
        for entry in filtered:
            by_tid[entry.tid].append(entry)
        for tid in sorted(by_tid):
            ranked = sorted(by_tid[tid], key=lambda entry: (entry.rank, -entry.lat_exec_sum, entry.pc_offset))
            for rank, entry in enumerate(ranked, 1):
                out.write(hotspot_entry_line(entry, rank) + "\n")


def default_output_path(hotpc: Path) -> Path:
    name = hotpc.name
    if name.endswith(".hotpc"):
        return hotpc.with_name(name[: -len(".hotpc")] + ".resolved.md")
    return hotpc.with_suffix(".resolved.md")


def default_filtered_hotpc_path(hotpc: Path) -> Path:
    name = hotpc.name
    if name.endswith(".hotpc"):
        return hotpc.with_name(name[: -len(".hotpc")] + ".filtered.hotpc")
    return hotpc.with_suffix(".filtered.hotpc")


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    hotpc_path = Path(args.hotpc).resolve()
    info_path = Path(args.info).resolve() if args.info else None
    source_root = args.source_root.resolve() if args.source_root else None
    output_path = args.output or default_output_path(hotpc_path)
    filtered_hotpc_path = args.filtered_hotpc or default_filtered_hotpc_path(hotpc_path)

    metadata, entries = parse_hotpc(hotpc_path)
    if not entries:
        raise SystemExit(f"no hotspot entries found in {hotpc_path}")
    # Keep metadata parsing intentionally active; future report versions can
    # surface extra provenance without changing the core parser.
    _ = metadata
    _ = parse_info(info_path)

    pcs = aggregate_hotspots(entries)
    resolved, diagnostics = resolve_hotspots(pcs, source_root, args.compile_commands)
    write_filtered_hotpc(filtered_hotpc_path, hotpc_path, metadata, entries, resolved)
    write_report(output_path, hotpc_path, info_path, filtered_hotpc_path, resolved, diagnostics, source_root, args.top)
    print(f"wrote {output_path}")
    print(f"wrote {filtered_hotpc_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
