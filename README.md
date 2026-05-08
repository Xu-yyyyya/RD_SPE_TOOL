# RD_SPE_TOOL

`RD_SPE_TOOL` 是面向 ARM64 Linux 的内存局部性分析工具。当前工具包含两个主要能力：

1. 使用 ARM SPE 采样获取热点访存指令 PC，并输出可跨次解释的 `.hotpc` 热点清单。
2. 使用 `targeted_rd` 二阶段对热点 PC 做 execute breakpoint 稀疏采样，并通过内核模块维护 watchpoint reservoir，输出近似 temporal reuse distance 的 `log2` 直方图。

工具支持 `LD_PRELOAD` 注入，因此可以用于没有源码的二进制程序；如果程序显式调用 `rd_start()` / `rd_stop()`，则以显式窗口为准，否则 `targeted_rd` 会使用进程生命周期自动窗口。

## 目录结构

```text
RD_SPE_TOOL/
  src/          C++ runtime、preload 入口、ARM SPE 解析、targeted_rd 控制器
  include/      公共头文件与 kernel module UAPI
  kernel/       rd_wpctl 内核模块
  postproc/     热点解析、直方图绘图和旧格式后处理脚本
  bin/          示例程序和小型测试程序
Rdbench/
  rdbench_temporal_rd.c        可控 temporal RD 基准
  run_rdbench.sh               二阶段 Rdbench runner
  tmp/                         运行输出目录
```

## 适用平台

推荐环境：

- ARM64 Linux。
- 支持 ARM SPE 的处理器和内核，用于第一阶段热点发现。
- 支持 ARMv8 PMUv3 `mem_access`、hardware breakpoint、hardware watchpoint。
- glibc + `LD_PRELOAD` 环境。
- OpenMP / pthread 程序；新增线程主要通过 `pthread_create` hook 接入。
- `targeted_rd` 需要 root 或等价权限来装载内核模块和使用 perf/hw breakpoint。

当前 `targeted_rd` 的 RD 语义是 per-thread temporal RD。不同线程之间对同一地址的跨线程 reuse 不会合并为一个 reuse pair。

## 依赖

常见依赖包：

```bash
sudo apt install build-essential g++ make libpfm4-dev libnuma-dev \
  linux-headers-$(uname -r) python3 python3-matplotlib binutils
```

如果系统限制 perf 访问，需要按本机策略调整权限，例如降低 `kernel.perf_event_paranoid` 或使用 root 运行。

## 构建

在仓库根目录执行：

```bash
make -C RD_SPE_TOOL -j
make -C RD_SPE_TOOL kernel-module
make -C Rdbench
```

主要产物：

```text
RD_SPE_TOOL/lib/librd.so
RD_SPE_TOOL/lib/librd.a
RD_SPE_TOOL/kernel/rd_wpctl.ko
Rdbench/rdbench_temporal_rd
```

清理：

```bash
make -C RD_SPE_TOOL clean
make -C RD_SPE_TOOL kernel-clean
make -C Rdbench clean
```

## 工作流概览

### 第一阶段：ARM SPE 热点发现

第一阶段使用 `RD_MODE=perp` 和 ARM SPE `ARM_SPE:LOADSTORE` 采样。输出包括：

```text
<name>.info
<name>.hotpc
<name>.t<tid>.sample0
```

ARM SPE 样本记录为 24 字节：

```text
u64 addr, u64 time, u64 pc
```

`.info` 中包含 `sample_record_bytes=24`、`sample_record_fields=addr,time,pc`、模块映射表和热点摘要。`.hotpc` 使用 `module_offset` 表示热点 PC，便于第二阶段在新进程中重定位。

示例：

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

解析热点到源码或反汇编：

```bash
python3 RD_SPE_TOOL/postproc/resolve_hotspots.py \
  build/spe_run.hotpc \
  --output build/spe_run.resolved.txt
```

### 第二阶段：targeted RD

第二阶段读取 `.hotpc`，只接受主二进制中的支持指令。用户态负责读取热点、重定位 PC、预解码 AArch64 load/store；内核模块负责 breakpoint、watchpoint、reservoir、`mem_access` 读取和 log2 直方图。

先装载模块：

```bash
sudo insmod RD_SPE_TOOL/kernel/rd_wpctl.ko
```

运行目标程序。`/dev/rd_wpctl` 默认权限为 `0600`，通常需要以 root 启动二阶段进程：

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

输出：

```text
build/rd2_run.rd2.info
build/rd2_run.rd2.t<tid>.hist.log2.txt
```

`*.hist.log2.txt` 格式：

```text
pc_offset    bucket_lo    bucket_hi    count
0x3278       4096         8191         8
```

log2 桶语义：

```text
bucket 0: delta = 0
bucket 1: delta = 1
bucket 2: delta = [2, 3]
bucket 3: delta = [4, 7]
...
```

## 运行参数

### 通用环境变量

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `RD_ENABLE` | 未启用 | 设置后激活 `librd.so` 构造入口。 |
| `RD_MODE` | 空 | `perp`、`noperp`、`pf`、`targeted_rd`。 |
| `RD_NAME` | `rd` | 输出文件名前缀，可包含目录。 |
| `RD_TARGET` | 空 | 仅当 `/proc/self/comm` 匹配该值时启用。 |
| `RD_PIDNAME` | `0` | 非零时把 PID 追加到 `RD_NAME` 后。 |
| `RD_PIN_CPU` | `0` | 第一阶段按线程最近 CPU 尝试绑核。 |
| `RD_BUFSIZE` | `1` | perf ring buffer 大小，单位 MiB，向下取 2 的幂。 |
| `RD_AUXBUFSIZE` | `1` | ARM SPE AUX buffer 大小，单位 MiB，向下取 2 的幂。 |

### 第一阶段参数

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `RD_PERIOD` | `0` | ARM SPE 采样周期。为 0 时不会产生 SPE 样本。 |
| `RD_HOTSPOT_TOP_K` | `4` | 每线程写入 `.hotpc` 的主二进制热点 PC 数量。 |

### 第二阶段参数

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `RD_TARGET_FILE` | 必填 | 第一阶段或 synthetic Rdbench 生成的 `.hotpc`。 |
| `RD_BP_SAMPLE_PERIOD` | `1024` | execute breakpoint 的稀疏样本周期。 |
| `RD_WP_CAPACITY` | `4` | 每线程 watchpoint reservoir 容量。 |
| `RD_RD_EVENT` | `mem_access` | RD 轴事件名，当前只支持 `mem_access`。 |

## 窗口语义

二阶段支持两种窗口：

- 纯 `LD_PRELOAD` 二进制：初始化完成后自动打开 fallback 窗口，持续到进程结束。
- 显式源码窗口：应用调用 `rd_start(tag)` / `rd_stop()`，第一次显式 `rd_start()` 会清空自动窗口已采集数据。

C 接口声明在 `RD_SPE_TOOL/include/rd.h`。示例：

```c
#include "rd.h"

rd_start("main_loop");
run_hot_loop();
rd_stop();
```

## Rdbench 与准确度测试

构建 Rdbench：

```bash
make -C Rdbench
```

运行精确次数测试：

```bash
sudo ./Rdbench/run_rdbench.sh \
  --hotspots 4 \
  --exact-hotspot-profiles "100:10000;1000:20000;5000:60000;10000:20000" \
  --bp-period 1024 \
  --wp-capacity 4 \
  --name sample_h4_p1024
```

绘制观测直方图：

```bash
python3 RD_SPE_TOOL/postproc/plot_rd_hist.py \
  Rdbench/tmp/sample_h4_p1024.rd2.t*.hist.log2.txt \
  -o sample_h4_p1024_hist.png
```

相对输出路径会写入 `RD_SPE_TOOL/postproc/out/`。

绘制真值与观测对比：

```bash
python3 RD_SPE_TOOL/postproc/plot_rd_acc.py \
  --manifest Rdbench/tmp/sample_h4_p1024.hotpc \
  --hist Rdbench/tmp/sample_h4_p1024.rd2.t*.hist.log2.txt \
  --x-max-rd 300000 \
  -o sample_h4_p1024_compare.png
```

Rdbench 的完整参数说明见 `Rdbench/README.md`。

## 输出文件说明

### 第一阶段 `.info`

常见字段：

```text
sample_record_bytes=24
sample_record_fields=addr,time,pc
sample_pc_present=1
pc_identity=raw_va
module_map_version=1
module_map=...
hotspot_manifest=<name>.hotpc
```

### 第一阶段 `.hotpc`

热点行格式：

```text
hotspot=<tid> <rank> <sample_count> <module_id> <pc_offset> <path>
```

`pc_offset = pc - vm_start + file_offset`，用于把本次运行的虚拟地址还原成稳定的“模块 + 文件偏移”。

### 第二阶段 `.rd2.info`

常见字段：

```text
targeted_rd_backend=kernel_module
targeted_rd_seed_source=execute_breakpoint
targeted_rd_rd_source=kernel_perf_event_read_value
breakpoint_sample_period=1024
reservoir_capacity=4
target_count=...
thread=<tid> <cpu> <candidate_samples> <reservoir_seen> <accepted> <rejected> <hits> <evictions> <dropped>
seed_samples=...
watchpoint_hits=...
```

其中 `candidate_samples` 是 breakpoint 稀疏候选流数量，`seed_samples` 是 reservoir 接受后真正进入 watchpoint 的 seed 数量。

## 设计限制

- 当前二阶段只支持 ARM64。
- `targeted_rd` 只处理主二进制 `.hotpc` 热点。
- 支持的热点指令子集为 AArch64 标量 `ldr/str/ldur/stur`，地址形式包括 `[base]`、`[base,#imm]`、`[base,index{,extend #shift}]`。
- 每线程独立统计；跨线程 reuse 不会合并。
- watchpoint 数量受硬件限制，`RD_WP_CAPACITY` 不应超过平台可用 watchpoint 数。
- `RD_BP_SAMPLE_PERIOD` 越小，候选样本越多，开销越高；越大，统计方差越大。

## 常见错误与处理

### `cannot open /dev/rd_wpctl`

内核模块未装载、设备节点不存在，或当前用户没有权限：

```bash
make -C RD_SPE_TOOL kernel-module
sudo insmod RD_SPE_TOOL/kernel/rd_wpctl.ko
ls -l /dev/rd_wpctl
```

默认设备权限是 `0600 root:root`。直接用 root 运行二阶段，或在本机实验环境中临时调整设备权限。

### `RD_TARGET_FILE is required for RD_MODE=targeted_rd`

二阶段缺少热点输入：

```bash
export RD_TARGET_FILE=build/spe_run.hotpc
```

### `kernel targeted_rd only supports RD_RD_EVENT=mem_access`

当前二阶段只支持 `mem_access`，不要设置其他 `RD_RD_EVENT`。

### `.rd2.info` 中 `rejected_target_count` 非 0

热点 PC 对应的指令或地址模式不在支持子集内。检查：

```bash
grep '^rejected_target=' build/rd2_run.rd2.info
python3 RD_SPE_TOOL/postproc/resolve_hotspots.py build/spe_run.hotpc
```

### `seed_samples=0`

常见原因：

- `.hotpc` 与当前二阶段运行的二进制不匹配。
- `RD_BP_SAMPLE_PERIOD` 过大，运行时间太短。
- 热点全部被过滤。
- 未装载内核模块或权限不足。
- 目标程序没有执行到热点路径。

### 没有 `.sample0` 或 `.hotpc`

检查：

- `RD_ENABLE=1` 是否设置。
- `RD_MODE=perp` 是否设置。
- `RD_PERIOD` 是否为正数。
- 目标平台是否支持 ARM SPE。
- 输出目录是否存在并可写。

### 内核模块编译失败

确认内核头文件匹配当前内核：

```bash
uname -r
ls /lib/modules/$(uname -r)/build
```

安装对应 `linux-headers-$(uname -r)` 后重新构建。

### perf 权限错误

使用 root 运行，或按系统安全策略调整 perf 权限：

```bash
cat /proc/sys/kernel/perf_event_paranoid
```

## 安全提示

`targeted_rd` 依赖内核模块、perf event、hardware breakpoint/watchpoint。只在受控环境中对可信程序使用；不要对未知二进制或生产服务直接装载实验模块。
