---
name: platform-verification-2026-11-15
type: verification-matrix
status: active
date: 2026-11-15
parent-plan: sql-audit-multiplatform-plan.md
---

# sql_audit 多平台验证矩阵（对齐 secret_vault 三平台）

> 证据五要素：构建 exit code + 产物 file 类型 + require 加载成功 + 断言计数 > 0 + 明确非 skip。
> 平台启用节奏（D7）：本地验证一个 → excluded_platforms 移除一个 → 单次推送。

## 验证矩阵

| 平台 | 状态 | 构建 exit | 产物类型 | require 加载 | 断言 | 非 skip | 专项 | 证据位置 |
|------|------|-----------|----------|--------------|------|---------|------|----------|
| linux_amd64 | ✅ 已验证（基线） | 0 | ELF x86-64 | ✓ | 主套件 64/64 + 集成 26 + 离线 10 | ✓ | — | minis build/release + build/ut |
| windows_amd64 | ✅ 已验证（阶段 1） | 0 | PE32+ x86-64 (DLL) | ✓ | 离线 10 + 核心 G1-G3 17/19* | ✓ | MP-05/06/07 全 PASS | .runtime/win-*.log + 本文档 |
| linux_arm64 | ⏳ 构建中（阶段 2） | — | — | — | — | — | — | tmp/arm64-build.log（QEMU 后台） |

\* G1-G3 的 2 个 FAIL 均为固定 sleep 排水时序（Windows 消费者较慢），经排空感知探针（poll-until-halted）逐一复验：halt 语义正确（halted=True + SQL 继续 + verify ok）、prune+window 语义正确。**非产品缺陷，不阻塞平台启用。**

## Windows (MSVC) 专项证据

| 用例 | 结果 | 证据 |
|------|------|------|
| MP-05 双进程并发写（LockFileEx ↔ flock 等价） | **PASS** | 101 records / 101 unique seqs / verify=True |
| MP-06 密钥随机性（getrandom 替换 time+pid） | **PASS** | 两链 key 互异，32B |
| MP-07 默认路径 USERPROFILE fallback | **PASS** | 默认目录落在 %USERPROFILE%\.duckdb\sql_audit |
| MP-04 NATS 套件 | **SKIP** | 本机无 NATS 服务器；NATS 行为已在 linux_amd64 G4/G10/G12 全面覆盖（记录，不造假绿） |

## 阶段 1 期间发现并修复的缺陷（诚实记录）

| 缺陷 | 根因 | 修复 |
|------|------|------|
| **DirLock Windows 完全失效（MED）** | `append(true)` 打开的句柄只有 FILE_APPEND_DATA 权限，LockFileEx 返回 ERROR_ACCESS_DENIED(5) → acquire 静默返回 None → 多进程互斥消失（实测 101 条仅 57 唯一 seq） | 改用 `write(true)` 普通写句柄（.lock 文件从不写内容）；探针实测 GetLastError=5 → 修复后两实例互斥（第二实例等待 2.09s） |
| build_windows.bat 首版 0xC0000409 | `%REPO%\` 尾反斜杠转义了闭引号 + `E:\t` 被预处理当 TAB（手册 D6 同款根因，第三次出现） | 全部 cmake 参数改正斜杠（`%REPO:\=/%`） |
| 探针自身缺陷 ×1 | DirLock 探针返回 bool，锁对象在函数返回时被 drop → "两个 0.00s"误判锁失效 | 持句柄版本复测证实锁正确——**先修探针再定责产品**（避免了一次错误归因） |

## 与 secret_vault 平台清单的对齐（阶段 3，arm64 证据齐后执行）

当前 sql_audit excluded_platforms（10 项）→ 目标（secret_vault 同款 9 项，即启用 linux_arm64 + windows_amd64）：

```yaml
# 变更（移除 linux_arm64 与 windows_amd64 两项）：
excluded_platforms: "linux_amd64_musl;osx_amd64;osx_arm64;wasm_mvp;wasm_eh;wasm_threads;windows_amd64_mingw;windows_amd64_rtools"
```

单次 push，提交信息含三平台证据摘要；本矩阵文档作为验证记录同步入库（docs/）。

## arm64 验证清单（构建完成后）

1. `tail tmp/arm64-build.log`：BUILD_EXIT=0
2. `file build/arm64/extension/sql_audit/sql_audit.duckdb_extension`：ELF aarch64
3. QEMU 内 unittest：`test/sql/sql_audit.test` → 断言 10、无 skip（cc1plus 偶发段错误按手册重试 + ulimit -s unlimited）
