# Changelog

## 1.0.0 (2026-10-14)

### 安全 / Security
- 文件巡检跳过 FIFO、设备等非普通文件，修复 Web 目录中放置命名管道导致巡检线程永久阻塞的问题。 / File scan skips non-regular files (a FIFO in the webroot could hang the scanner forever).
- `follow_symlinks=false` 时同时跳过文件级符号链接，避免以 root 读取 Web 目录外的文件。 / File symlinks are no longer followed unless `follow_symlinks` is enabled.
- `winevent.log_name` 增加白名单校验，防止 PowerShell 命令注入。 / Whitelist `winevent.log_name` to prevent PowerShell command injection.

### 修复 / Fixes
- 文件内容扫描始终限长读取（防 TOCTOU 内存膨胀）。 / Content scan always reads at most `max_file_bytes`.
- pcapng：正确处理 2 的幂时间精度（`if_tsresol` 高位）；新 Section 重置接口表。 / pcapng: power-of-two `if_tsresol`, per-section interface reset.
- HTTP 分块/multipart 边界、日志半行与 UTF-8 分批写入、IIS 表头、基线保存、跨天日志与去重等，详见 [OPTIMIZATION.md](OPTIMIZATION.md)。

### 性能 / Performance
- 文件特征正则在模块加载时预编译。 / File-scan signatures are precompiled.
- 文件变更判定约 10 倍提速（见 `benchmarks/`）。

### 其他 / Other
- 新增回归测试与 GitHub Actions（Python 3.9–3.12）。 / Regression tests and CI.
