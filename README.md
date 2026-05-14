# RD_SPE_TOOL

`RD_SPE_TOOL` 是面向 ARM64 Linux 的内存局部性分析工具。工具以
`LD_PRELOAD` 注入运行时库为入口，先用 ARM SPE 找到热点访存指令，再在第二阶段针对这些热点
PC 采集近似 temporal reuse distance，并输出按热点、use-reuse pair 和可选调用上下文聚合的
`log2` 直方图。

当前版本的主要能力：

- 第一阶段：ARM SPE `LOADSTORE` 采样，输出稳定的热点 PC 清单 `.hotpc`。
- 第二阶段：`targeted_rd` 读取 `.hotpc`，通过 execute breakpoint 产生候选 seed，通过内核模块维护
  watchpoint slot，使用 `mem_access` 计算 reuse distance。
- use-reuse pair：在 watchpoint reuse 命中时同时记录 seed PC 和 reuse PC，输出 pair 级直方图。
- 调用上下文：支持 `off`、`fp`、`dwarf` 三种模式；DWARF 模式保存 raw 快照并离线展开调用链。

## 目录结构

```text
RD_SPE_TOOL/
  src/          preload 入口、ARM SPE 解析、targeted_rd 用户态控制器、pthread hook
  include/      公共头文件、rd_start/rd_stop API、kernel module UAPI
  kernel/       rd_wpctl 内核模块，负责 breakpoint/watchpoint/mem_access 数据面
  postproc/     热点解析、直方图绘图、DWARF use-reuse 调用路径解析脚本
  bin/          示例程序、smoke test 和 targeted_rd 微基准
  lib/          构建生成的 librd.so / librd.a
```

仓库根目录的 `Rdbench/` 是准确度基准，不属于运行时核心工具，但可用于生成 synthetic `.hotpc` 和真值直方图。

## 平台与依赖

推荐平台：

- ARM64 Linux。
- 支持 ARM SPE，用于第一阶段热点发现。
- 支持 ARMv8 PMUv3 `mem_access`、hardware breakpoint、hardware watchpoint。
- glibc + `LD_PRELOAD` 环境。
- pthread/OpenMP 线程模型；新增线程通过 `pthread_create` hook 注册到工具。
- 第二阶段需要 root 或等价权限，用于装载内核模块和使用 perf/hardware debug 资源。

安装常用依赖：

```bash
sudo apt install build-essential g++ make libpfm4-dev libnuma-dev \
  linux-headers-$(uname -r) python3 python3-pip python3-matplotlib \
  binutils
python3 -m pip install -r RD_SPE_TOOL/postproc/requirements.txt
```

DWARF 离线调用链解析依赖 ELF unwind 信息；源码行显示依赖调试信息，例如 `-g` 或独立 debug file。

## 构建

在仓库根目录执行：

```bash
make -C RD_SPE_TOOL -j
make -C RD_SPE_TOOL kernel-module
```

主要产物：

```text
RD_SPE_TOOL/lib/librd.so
RD_SPE_TOOL/lib/librd.a
RD_SPE_TOOL/kernel/rd_wpctl.ko
RD_SPE_TOOL/bin/*
```

清理：

```bash
make -C RD_SPE_TOOL clean
make -C RD_SPE_TOOL kernel-clean
```

## 第一阶段：ARM SPE 热点发现

第一阶段使用 `RD_MODE=perp`，通过 ARM SPE `ARM_SPE:LOADSTORE` 采样访存地址、时间和指令 PC。

```bash
mkdir -p build

env RD_ENABLE=1 \
    RD_MODE=perp \
    RD_PERIOD=100000 \
    RD_HOTSPOT_TOP_K=6 \
    RD_NAME=build/spe_run \
    LD_PRELOAD=$PWD/RD_SPE_TOOL/lib/librd.so \
    ./your_program arg1 arg2
```

输出：

```text
build/spe_run.info
build/spe_run.hotpc
build/spe_run.t<tid>.sample0
```

ARM SPE `.sample0` 记录布局固定为：

```text
u64 addr, u64 time, u64 pc
```

`.hotpc` 使用模块文件偏移表示热点 PC：

```text
pc_offset = pc - vm_start + file_offset
```

这样第二阶段在新进程中可以结合当前 `/proc/self/maps` 把热点重定位到本次运行的绝对 PC。

解析热点到符号、源码行和反汇编：

```bash
python3 RD_SPE_TOOL/postproc/resolve_hotspots.py \
  build/spe_run.hotpc \
  --output build/spe_run.resolved.txt
```

## 第二阶段：targeted RD

第二阶段读取 `.hotpc`，只接收主二进制中可解码的 AArch64 标量 load/store 热点。用户态控制器负责：

- 读取和过滤 `.hotpc`。
- 重定位热点 PC。
- 通过 `objdump` 预解码有效地址模板。
- 为线程绑定 CPU 并注册到内核模块。
- 在进程退出时通过 ioctl 拉取统计和直方图。

内核模块负责：

- 注册 execute breakpoint 和 watchpoint。
- 根据 breakpoint 命中寄存器计算 seed VA。
- 使用 idle-first per-slot replacement 策略选择 watchpoint slot。
- 在 watchpoint reuse 命中时读取 `mem_access` 并计算 `delta = hit - seed - 1`。
- 更新 per-target 直方图、use-reuse pair 直方图和可选调用上下文数据。

装载模块：

```bash
sudo insmod RD_SPE_TOOL/kernel/rd_wpctl.ko
```

运行目标程序：

```bash
sudo bash -c "cd $PWD && env RD_ENABLE=1 \
  RD_MODE=targeted_rd \
  RD_TARGET_FILE=build/spe_run.hotpc \
  RD_NAME=build/rd2_run \
  RD_BP_SAMPLE_PERIOD=1024 \
  RD_WP_CAPACITY=4 \
  LD_PRELOAD=$PWD/RD_SPE_TOOL/lib/librd.so \
  ./your_program arg1 arg2"
```

卸载模块：

```bash
sudo rmmod rd_wpctl
```

## 窗口语义

`targeted_rd` 支持纯二进制 `LD_PRELOAD` 场景。若程序不调用 `rd_start()` / `rd_stop()`，工具会在初始化和初始线程注册完成后自动打开 fallback 窗口，直到进程退出。

如果应用显式调用 `rd_start()`，工具会关闭自动窗口、清空自动窗口数据，然后以显式窗口为准：

```c
#include "rd.h"

rd_start("main_loop");
run_hot_loop();
rd_stop();
```

## 输出文件

第二阶段基础输出：

```text
<name>.rd2.info
<name>.rd2.t<tid>.hist.log2.txt
<name>.rd2.t<tid>.pair.hist.log2.txt
```

`*.hist.log2.txt` 是按 seed hotspot 聚合的 RD 直方图：

```text
pc_offset    bucket_lo    bucket_hi    count
0x3278       4096         8191         8
```

`*.pair.hist.log2.txt` 是按 use-reuse pair 聚合的 RD 直方图：

```text
seed_pc_offset  seed_context_id  reuse_pc        reuse_context_id  bucket_lo  bucket_hi  count
0x3278          3                0xffffaabbcc00  7                 65536      131071     12
```

`log2` 桶语义：

```text
bucket 0: delta = 0
bucket 1: delta = 1
bucket 2: delta = [2, 3]
bucket 3: delta = [4, 7]
...
```

`.rd2.info` 包含运行配置、目标热点、线程统计和调用上下文统计。常见字段包括：

```text
targeted_rd_backend=kernel_module
targeted_rd_seed_source=execute_breakpoint
targeted_rd_rd_source=kernel_perf_event_read_value
breakpoint_sample_period=1024
reservoir_capacity=4
target_count=...
target=<index> <pc_offset> <abs_pc> <samples> <mnemonic> <operands>
thread=<tid> <cpu> <candidate_samples> <reservoir_seen> <accepted> <rejected> <hits> ...
seed_samples=...
watchpoint_hits=...
```

## 调用上下文模式

通过 `RD_CALLCHAIN_MODE` 选择调用上下文采集方式：

| 模式 | 输出 | 适用场景 |
| --- | --- | --- |
| `off` | 只输出基础 hist 和 pair hist | 默认模式，开销最低。 |
| `fp` | 额外输出 `*.contexts.txt` | 程序保留 frame pointer，例如 `-fno-omit-frame-pointer`。 |
| `dwarf` | 额外输出 `*.dwarf.raw.bin` / `*.dwarf.raw.txt` | 程序无 FP，但有可用 `.eh_frame` / DWARF unwind 信息。 |

FP 模式在内核中沿用户态 FP 链展开，最大深度由 `RD_WPCTL_MAX_CALLCHAIN_DEPTH` 限制。该模式开销低，但对 frameless/leaf/tail-call 情况不完整。

DWARF 模式在内核中只保存 seed/reuse 寄存器和用户栈快照，不在热路径解析 DWARF。离线解析示例：

```bash
sudo bash -c "cd $PWD && env RD_ENABLE=1 \
  RD_MODE=targeted_rd \
  RD_TARGET_FILE=build/spe_run.hotpc \
  RD_NAME=build/rd2_dwarf \
  RD_CALLCHAIN_MODE=dwarf \
  RD_DWARF_STACK_BYTES=8192 \
  RD_DWARF_EVENT_CAPACITY=16384 \
  LD_PRELOAD=$PWD/RD_SPE_TOOL/lib/librd.so \
  ./your_program"

python3 RD_SPE_TOOL/postproc/resolve_dwarf_pairs.py \
  --info build/rd2_dwarf.rd2.info \
  --raw build/rd2_dwarf.rd2.t*.dwarf.raw.bin \
  --binary ./your_program \
  --output-prefix build/rd2_dwarf
```

后处理输出：

```text
build/rd2_dwarf.dwarf.pair_context.hist.log2.txt
build/rd2_dwarf.dwarf.long_rd.report.md
```

报告会以调用树展示 use-side 和 reuse-side 调用路径，并标注 `USE HIT` 与 `REUSE HIT`。

## 环境变量

### 通用变量

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `RD_ENABLE` | 未启用 | 设置后激活 `librd.so` 构造入口。 |
| `RD_MODE` | 空 | `perp`、`noperp`、`pf`、`targeted_rd`。 |
| `RD_NAME` | `rd` | 输出文件名前缀，可包含目录。 |
| `RD_TARGET` | 空 | 仅当 `/proc/self/comm` 匹配该值时启用。 |
| `RD_PIDNAME` | `0` | 非零时把 PID 追加到 `RD_NAME` 后。 |
| `RD_PIN_CPU` | `0` | 第一阶段按线程最近 CPU 尝试绑核。 |
| `RD_BUFSIZE` | `1` | perf ring buffer 大小，单位 MiB。 |
| `RD_AUXBUFSIZE` | `1` | ARM SPE AUX buffer 大小，单位 MiB。 |

### 第一阶段变量

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `RD_PERIOD` | `0` | ARM SPE 采样周期；为 0 时不会产生 SPE 样本。 |
| `RD_HOTSPOT_TOP_K` | `4` | 每线程写入 `.hotpc` 的主二进制热点 PC 数量。 |

### 第二阶段变量

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `RD_TARGET_FILE` | 必填 | 第一阶段或 Rdbench 生成的 `.hotpc`。 |
| `RD_BP_SAMPLE_PERIOD` | `1024` | execute breakpoint 稀疏采样周期。 |
| `RD_WP_CAPACITY` | `4` | 每线程 watchpoint slot 数量，不应超过硬件可用 watchpoint 数。 |
| `RD_RD_EVENT` | `mem_access` | RD 轴事件名；当前只支持 `mem_access`。 |
| `RD_CALLCHAIN_MODE` | `off` | `off`、`fp`、`dwarf`。 |
| `RD_DWARF_STACK_BYTES` | `8192` | DWARF 模式每个快照复制的用户栈字节数，最大 8192。 |
| `RD_DWARF_EVENT_CAPACITY` | `16384` | DWARF 模式每线程 raw event 容量。 |

## 后处理工具

解析热点：

```bash
python3 RD_SPE_TOOL/postproc/resolve_hotspots.py build/spe_run.hotpc \
  --output build/spe_run.resolved.txt
```

绘制观测 RD 直方图，输出到 `RD_SPE_TOOL/postproc/out/`：

```bash
python3 RD_SPE_TOOL/postproc/plot_rd_hist.py \
  build/rd2_run.rd2.t*.hist.log2.txt \
  --x-max-rd 300000 \
  -o rd2_run_hist.png
```

绘制 Rdbench 真值与观测对比：

```bash
python3 RD_SPE_TOOL/postproc/plot_rd_acc.py \
  --manifest Rdbench/tmp/sample.hotpc \
  --hist Rdbench/tmp/sample.rd2.t*.hist.log2.txt \
  --x-max-rd 300000 \
  -o sample_compare.png
```

解析 DWARF use-reuse 调用路径：

```bash
python3 RD_SPE_TOOL/postproc/resolve_dwarf_pairs.py \
  --info build/rd2_dwarf.rd2.info \
  --raw build/rd2_dwarf.rd2.t*.dwarf.raw.bin \
  --binary ./your_program \
  --output-prefix build/rd2_dwarf \
  --top 20
```

## 设计限制

- 当前二阶段只支持 ARM64。
- `targeted_rd` 默认只处理主二进制热点；共享库热点第一版不作为目标。
- 支持的热点指令子集为 AArch64 标量 `ldr/str/ldur/stur` 及当前解码器覆盖的地址模式。
- RD 语义是 per-thread temporal RD；跨线程 reuse 不合并。
- watchpoint 数量受硬件限制；若 `RD_WP_CAPACITY` 超过硬件能力，线程注册会失败。
- `RD_BP_SAMPLE_PERIOD` 越小，候选越多、开销越高；越大，采样方差越大。
- DWARF 模式 raw event buffer 满时，只丢调用上下文事件，不影响基础 RD 直方图。
- FP 模式依赖标准 FP frame；无 FP、尾调用、frameless 函数会导致调用链不完整。

## 常见错误与处理

### `cannot open /dev/rd_wpctl`

内核模块未装载、设备节点不存在，或当前用户无权限：

```bash
make -C RD_SPE_TOOL kernel-module
sudo insmod RD_SPE_TOOL/kernel/rd_wpctl.ko
ls -l /dev/rd_wpctl
```

默认设备权限通常需要 root 运行二阶段。

### `RD_TARGET_FILE is required for RD_MODE=targeted_rd`

二阶段缺少热点输入：

```bash
export RD_TARGET_FILE=build/spe_run.hotpc
```

### `kernel targeted_rd only supports RD_RD_EVENT=mem_access`

当前二阶段只支持 `mem_access`。不要把 `RD_RD_EVENT` 设置成其他事件。

### `.rd2.info` 中 `rejected_target_count` 非 0

部分热点指令不在当前解码支持范围内。检查：

```bash
grep '^rejected_target=' build/rd2_run.rd2.info
python3 RD_SPE_TOOL/postproc/resolve_hotspots.py build/spe_run.hotpc
```

### `seed_samples=0` 或 `watchpoint_hits=0`

常见原因：

- `.hotpc` 与当前二阶段二进制不匹配。
- `RD_BP_SAMPLE_PERIOD` 太大，程序运行时间太短。
- 热点 PC 没有在第二阶段执行。
- 热点全部被过滤或指令不支持。
- 内核模块未装载或权限不足。
- `RD_WP_CAPACITY` 超过硬件 watchpoint 能力。

### 没有 `.sample0` 或 `.hotpc`

检查：

- `RD_ENABLE=1` 是否设置。
- `RD_MODE=perp` 是否设置。
- `RD_PERIOD` 是否为正数。
- 目标平台是否支持 ARM SPE。
- 输出目录是否存在且可写。

### DWARF 报告出现 `??@??:0`

这通常表示缺少符号或源码行信息。`.eh_frame` 足够做 unwind，但源码行需要调试信息：

```bash
addr2line -f -C -e ./your_program 0x<offset>
```

如果二进制被 strip 且没有独立 debug file，报告只能显示有限符号或地址。

### 内核模块编译失败

确认内核头文件匹配当前内核：

```bash
uname -r
ls /lib/modules/$(uname -r)/build
```

安装对应 `linux-headers-$(uname -r)` 后重新构建。

## 安全提示

`targeted_rd` 依赖内核模块、perf event、hardware breakpoint/watchpoint 和用户态栈快照。只在受控环境中对可信程序使用；不要对未知二进制或生产服务直接装载实验模块。
