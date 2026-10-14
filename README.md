# webshell-watch

[![test](../../actions/workflows/test.yml/badge.svg)](../../actions/workflows/test.yml)
![python](https://img.shields.io/badge/python-3.9%2B-blue)
![license](https://img.shields.io/badge/license-MIT-green)

**[中文](#中文) | [English](#english)**

---

## 中文

### 简介
webshell-watch 是一个运行在 **Linux / Windows(IIS) 服务器**上的 **WebShell 防守监控工具**，用于发现服务器正被蚁剑（AntSword）、冰蝎（Behinder）、哥斯拉（Godzilla）等 WebShell 管理工具远控的迹象，并输出可直接处置的告警。

纯 Python 标准库实现，**无第三方依赖**；不连接外部地址、不主动发起请求，只读取本机日志、Web 目录文件和（可选）抓包数据。

### 功能
- **Web 访问日志分析**：nginx / apache / IIS W3C，支持实时跟踪与离线分析。日志在 TLS 解密后生成，HTTPS 站点同样有效。
- **Web 目录文件巡检**：基线比对（新增/修改/权限/属主）+ 脚本内容静态特征（PHP/JSP/ASP/ASPX）。
- **认证与账号审计**：Linux `auth.log`（SSH 爆破、sudo 提权、建号、SSH 公钥追加）；Windows 安全事件日志（4624/4625/4672/4720/4732/7045/4104）。
- **Windows 工具落地扫描**：Temp / Public / ProgramData 新增可执行文件。
- **流量分析**：离线 pcap / pcapng 分析、监控目录自动分析；Linux 可选 AF_PACKET 实时抓包；TLS ClientHello / JA3 指纹。
- **告警输出**：JSONL、可读摘要、syslog、Webhook，带去重与按天轮转。
- **可扩展规则**：JSON 自定义规则，可覆盖内置规则。

### 支持的检测（77 条内置规则）
| 类别 | 数量 | 示例 |
|---|---:|---|
| 蚁剑 AntSword | 13 | 客户端 UA、固定初始化载荷、z0/z1 参数、chr/hex 编码器 |
| 冰蝎 Behinder | 13 | 默认密钥、固定字节头、Java class/序列化魔数、UA 池与头部组合 |
| 哥斯拉 Godzilla | 14 | 响应 `16hex + Base64 + 16hex` 结构、畸形 Cookie、心跳式通信 |
| 加密隧道 TLS | 5 | JDK TLS 栈冒充浏览器、编程语言 TLS 库、JA3 已知指纹 |
| 通用 WebShell | 7 | 命令执行参数、Base64 代码、一句话马特征 |
| 防守告警 | 25 | 文件静态特征、上传目录脚本、SSH 爆破、提权、新服务、PowerShell 高危脚本块 |

完整列表：`python3 wsp.py rules`

### 安装

环境要求：Python 3.9+（Ubuntu 24.04 自带 3.12）。

**先试一下（不改系统，任何平台）**
```bash
python3 demo.py     # 构造仿真受害环境并跑完整检测链路
```

**Linux（Ubuntu 24.04 等，systemd）**
```bash
git clone https://github.com/tjut-lfl/webshell-watch.git && cd webshell-watch
sudo ./install.sh              # 安装并启动服务；--no-start 只安装；--uninstall 卸载
systemctl status webshell-watch
sudo wsp check
```
安装到 `/opt/webshell-watch`，配置 `/etc/webshell-watch/config.json`，告警 `/var/log/webshell-watch/`。
**强烈建议**让 nginx 记录请求体（配置片段见 `/etc/webshell-watch/nginx-request-body.conf`），否则加密型马的载荷不可见。

**Windows（IIS）**
```powershell
.\windows\wsp-windows.ps1 check                # 环境自检
.\windows\wsp-windows.ps1 start --foreground   # 前台试运行
.\windows\install-service.ps1                  # 管理员：注册开机自启计划任务
```
也可双击 `windows\启动自检.bat`。配置位于 `C:\ProgramData\webshell-watch\config.json`。

### 使用
```bash
sudo wsp start [--foreground] [--once] [--disable 模块]   # 守护监控
sudo wsp check                                             # 自检：权限、日志、规则、基线
sudo wsp analyze-log /var/log/nginx/access.log --from-beginning [--export out.jsonl]
sudo wsp filescan [--webroot /var/www] [--update-baseline] # 发布代码后更新基线
wsp analyze-pcap capture.pcapng
wsp rules                                                  # 列出规则
wsp report                                                 # 告警文件与统计
```
未安装时用 `python3 wsp.py <命令>`（Linux 入口 `linux/wsp-linux`）。

### 配置
`linux.json` / `windows.json` 结构相同，所有字段可省略。主要分区：

| 分区 | 作用 |
|---|---|
| `analyzer` | 告警阈值 `min_score`、尝试解密、禁用规则、启用的工具类别 |
| `weblog` | 访问日志来源与格式 |
| `filescan` | `webroots`、脚本扩展名、巡检间隔、`max_file_bytes`、`follow_symlinks`、排除目录 |
| `authlog` / `winevent` / `iislog` / `windrop` | 认证日志、Windows 事件日志、IIS 日志、落地目录 |
| `sniff` / `pcap` | 实时抓包（默认关闭）、pcap 监控目录 |
| `output` / `webhook` / `notify` | 输出目录、syslog、Webhook、去重 |
| `rules` | 自定义规则目录（示例 `rules/custom-rules.json`） |

详细部署与调优说明见 [docs/DEPLOYMENT.zh-CN.md](docs/DEPLOYMENT.zh-CN.md)，应急处置见 [INCIDENT-RESPONSE.md](INCIDENT-RESPONSE.md)。

### 测试
```bash
python3 lint_check.py                              # 语法与导入检查
python3 selftest.py                                # 端到端自测
PYTHONPATH=. python3 -m unittest discover -s tests -v  # 回归测试
```
CI（GitHub Actions）在 Python 3.9–3.12 上运行以上全部检查。

### 目录结构
```
wsp.py                 命令行入口
wsa/                   检测引擎（日志、文件、pcap、TLS、规则、告警、守护进程）
rules/                 自定义规则示例
linux/  linux.json     Linux 入口与默认配置
windows/ windows.json  Windows 入口、安装脚本与默认配置
install.sh             Linux 一键安装（systemd + logrotate）
demo.py selftest.py    演示与自测
tests/  benchmarks/    回归测试与性能基准
docs/                  详细文档
```

### 免责声明
本项目是**纯防守工具**，仅用于在你拥有或已获授权的服务器上检测入侵。它不包含任何攻击、利用或远控功能。请遵守当地法律法规；作者不对任何滥用或因使用本工具造成的损失负责。检测结果可能存在误报/漏报，不能替代专业应急响应。

### 许可证
[MIT](LICENSE) © 2026 tjut-lfl

---

## English

### Overview
webshell-watch is a **defensive WebShell monitoring tool** for **Linux and Windows (IIS) servers**. It detects signs that a server is being remotely controlled through WebShell managers such as **AntSword, Behinder (冰蝎) and Godzilla (哥斯拉)**, and produces actionable alerts.

Pure Python standard library, **zero third-party dependencies**. It never connects to external hosts or sends requests; it only reads local logs, web-root files and (optionally) packet captures.

### Features
- **Web access log analysis** — nginx / apache / IIS W3C, live tailing and offline analysis. Logs are written after TLS termination, so HTTPS sites are covered.
- **Web-root file scanning** — baseline diff (new / modified / permission / owner) plus static content signatures for PHP / JSP / ASP / ASPX.
- **Authentication auditing** — Linux `auth.log` (SSH brute force, sudo escalation, new users, appended SSH keys); Windows Security event log (4624/4625/4672/4720/4732/7045/4104).
- **Windows tool-drop scanning** — new executables in Temp / Public / ProgramData.
- **Traffic analysis** — offline pcap / pcapng, watched pcap directory, optional AF_PACKET live capture on Linux, TLS ClientHello / JA3 fingerprints.
- **Alert output** — JSONL, human-readable summary, syslog, webhook; deduplication and daily rotation.
- **Extensible rules** — custom JSON rules that can override built-ins.

### Supported detections (77 built-in rules)
| Category | Count | Examples |
|---|---:|---|
| AntSword | 13 | client UA, fixed init payload, z0/z1 params, chr/hex encoders |
| Behinder | 13 | default key, fixed byte headers, Java class / serialization magic, UA pool & header set |
| Godzilla | 14 | `16hex + Base64 + 16hex` response, malformed Cookie, heartbeat-like C2 |
| Encrypted tunnel (TLS) | 5 | JDK TLS stack claiming to be a browser, language TLS libs, known JA3 |
| Generic WebShell | 7 | command-exec params, Base64-encoded code, one-liner patterns |
| Defensive | 25 | file signatures, scripts in upload dirs, SSH brute force, privilege escalation, new services, risky PowerShell script blocks |

Full list: `python3 wsp.py rules`

### Installation

Requires Python 3.9+ (Ubuntu 24.04 ships 3.12).

**Try it first (no system changes, any OS)**
```bash
python3 demo.py     # builds a simulated compromised environment and runs the full pipeline
```

**Linux (Ubuntu 24.04 etc., systemd)**
```bash
git clone https://github.com/tjut-lfl/webshell-watch.git && cd webshell-watch
sudo ./install.sh              # install & start; --no-start to install only; --uninstall to remove
systemctl status webshell-watch
sudo wsp check
```
Installs to `/opt/webshell-watch`; config at `/etc/webshell-watch/config.json`; alerts in `/var/log/webshell-watch/`.
**Strongly recommended:** make nginx log request bodies (snippet in `/etc/webshell-watch/nginx-request-body.conf`); otherwise encrypted payloads are invisible.

**Windows (IIS)**
```powershell
.\windows\wsp-windows.ps1 check                # environment self-check
.\windows\wsp-windows.ps1 start --foreground   # trial run
.\windows\install-service.ps1                  # as Administrator: register a startup scheduled task
```
Or double-click `windows\启动自检.bat`. Config lives at `C:\ProgramData\webshell-watch\config.json`.

### Usage
```bash
sudo wsp start [--foreground] [--once] [--disable MODULE]  # run the daemon
sudo wsp check                                             # self-check: permissions, logs, rules, baseline
sudo wsp analyze-log /var/log/nginx/access.log --from-beginning [--export out.jsonl]
sudo wsp filescan [--webroot /var/www] [--update-baseline] # refresh baseline after deployments
wsp analyze-pcap capture.pcapng
wsp rules                                                  # list rules
wsp report                                                 # alert files & stats
```
Without installing, use `python3 wsp.py <command>` (Linux wrapper: `linux/wsp-linux`).

### Configuration
`linux.json` and `windows.json` share one schema; every field is optional. Main sections:

| Section | Purpose |
|---|---|
| `analyzer` | alert threshold `min_score`, decryption attempts, disabled rules, enabled tool families |
| `weblog` | access-log sources and formats |
| `filescan` | `webroots`, script extensions, interval, `max_file_bytes`, `follow_symlinks`, excludes |
| `authlog` / `winevent` / `iislog` / `windrop` | auth log, Windows events, IIS logs, drop directories |
| `sniff` / `pcap` | live capture (off by default), watched pcap directory |
| `output` / `webhook` / `notify` | output dir, syslog, webhook, dedup |
| `rules` | custom rule directory (see `rules/custom-rules.json`) |

Detailed deployment notes (Chinese): [docs/DEPLOYMENT.zh-CN.md](docs/DEPLOYMENT.zh-CN.md). Incident response: [INCIDENT-RESPONSE.md](INCIDENT-RESPONSE.md).

### Testing
```bash
python3 lint_check.py
python3 selftest.py
PYTHONPATH=. python3 -m unittest discover -s tests -v
```
GitHub Actions runs all of the above on Python 3.9–3.12.

### Project layout
```
wsp.py                 CLI entry point
wsa/                   detection engine (logs, files, pcap, TLS, rules, alerting, daemon)
rules/                 custom rule examples
linux/  linux.json     Linux wrapper and default config
windows/ windows.json  Windows wrappers, installer and default config
install.sh             Linux installer (systemd + logrotate)
demo.py selftest.py    demo and end-to-end self-test
tests/  benchmarks/    regression tests and benchmarks
docs/                  detailed documentation
```

### Disclaimer
This is a **purely defensive tool**, intended only for detecting intrusions on servers you own or are authorized to protect. It contains no attack, exploitation or remote-control functionality. Comply with applicable laws; the author accepts no liability for misuse or for any damage arising from use. Detection may produce false positives/negatives and does not replace professional incident response.

### License
[MIT](LICENSE) © 2026 tjut-lfl
