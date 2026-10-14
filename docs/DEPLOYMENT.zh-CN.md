# WebShell 防守监控（服务器端）

本目录为 2026-10-14 优化版。改动、验证结果和使用说明见
[`OPTIMIZATION.md`](../OPTIMIZATION.md)。新增边界回归测试可运行：
`python -m unittest discover -s tests -v`。

在 **Linux（Ubuntu 24.04 等）与 Windows（IIS）** 服务器上发现
「服务器正在被别人用蚁剑 / 冰蝎 / 哥斯拉之类的工具远控」，并给出可直接处置的告警。

**这是一个纯防守工具**：它不连接任何外部地址，不主动发起请求，只读取本机的
Web 访问日志、认证日志（Linux）/ 事件日志（Windows）与 Web 目录文件。
（网上很多同类资料讲的是「把工具代理指向攻击者电脑」，那是红队用法，与本站点无关。）

**两个平台版本**，共用同一套检测引擎与规则，只有数据源适配不同：

| | Linux 版 | Windows 版 |
|---|---|---|
| 入口 | `linux/wsp-linux` | `windows/wsp-windows.ps1` / `启动自检.bat` |
| 配置 | `linux.json` | `windows.json` |
| 安装 | `sudo ./install.sh`（systemd + logrotate） | `windows\install-service.ps1`（管理员，计划任务开机自启） |
| Web 日志 | nginx / apache，**可记录 POST 请求体** | IIS W3C 格式；IIS 不记录请求体，需 Advanced Logging 或前置 nginx |
| 认证/账号 | `/var/log/auth.log`：SSH 爆破、sudo 提权、建号 | Windows 安全事件日志：4624/4625/4672/4720/4732/7045/4104 |
| 文件巡检 | 脚本内容特征 + 777/属主异常 | 脚本内容特征（含 **ASPX/.NET 马**）+ 上传目录脚本 + web.config 篡改 |
| 额外能力 | 可选 AF_PACKET 抓包（明文 HTTP） | **工具落地目录扫描**（Temp/Public/ProgramData 新增 exe） |

---

## 0. 先在本机看它真的能工作（推荐第一步）

```bash
python3 demo.py          # Windows 上：python demo.py
```

它会在临时目录里造一套「已被 webshell 控制」的仿真环境（IIS 日志、nginx 日志、
auth.log、Windows 事件样本、含 ASPX/PHP 马的站点目录、落地的 exe），
跑完整检测链路并把告警打印出来。**不联网、不改系统配置**，删掉 `demo-output` 即清理干净。

这一步能让你在真部署前就知道：规则链路通不通、告警长什么样、哪些是误报。

---

## 1. 为什么服务器端要这样做

| 数据源 | 能看到什么 | 关键点 |
|---|---|---|
| **Web 访问日志** | 完整明文：URL、UA、参数、请求体、状态码 | 日志在 **TLS 解密之后**生成，所以 **HTTPS 站点同样有效** —— 这是服务器端最强的数据源 |
| **Web 目录文件** | 服务器上到底多了/改了什么文件 | 与日志交叉确认，基本可排除误报 |
| **认证日志 / 事件日志** | SSH 爆破、登录、提权、建号、服务安装 | webshell 只是入口，持久化与横向移动的证据在这里 |
| 网卡抓包（仅 Linux，可选） | 明文 HTTP；HTTPS 只能看 TLS 指纹 | 服务器侧 HTTPS 是密文，抓包**看不到**加密马载荷，因此默认关闭 |

> 结论：**以日志为主，文件为辅，抓包兜底**。只开抓包在 HTTPS 站点上几乎无效。

---

## 2. Linux 版部署（Ubuntu 24.04）

```bash
# 1) 上传整个目录到服务器，例如 /root/webshell-watch
cd /root/webshell-watch

# 2) 先看看它能不能抓出东西
python3 demo.py

# 3) 一键安装（写 /opt、/etc、systemd 单元、logrotate，并自动自检）
sudo ./install.sh

# 4) 看状态与告警
systemctl status webshell-watch
journalctl -u webshell-watch -f
tail -f /var/log/webshell-watch/alerts-$(date +%Y%m%d).jsonl
wsp report
```

安装脚本做的事：

| 路径 | 内容 |
|---|---|
| `/opt/webshell-watch/` | 程序本体（纯标准库，无第三方依赖） |
| `/etc/webshell-watch/config.json` | 配置（由 `linux.json` 生成，并自动关闭 Windows 专属模块） |
| `/etc/webshell-watch/nginx-request-body.conf` | **必须处理**：让 nginx 记录请求体的配置片段 |
| `/var/log/webshell-watch/` | `alerts-*.jsonl`（结构化告警）、`alerts-*.log`（摘要）、`watch-*.log`（运行日志） |
| `/var/lib/webshell-watch/` | 文件基线、pcap 目录 |
| `/etc/systemd/system/webshell-watch.service` | 开机自启 + 崩溃自动重启 |
| `/etc/logrotate.d/webshell-watch` | 日志轮转（保留 30 天） |

环境要求：只要求 `python3`（Ubuntu 24.04 自带 3.12），
**不需要 pip、不需要 PyYAML、不需要 scapy/dpkt。**

### 2.1 Linux 上一定要做的一步：让 nginx 记录请求体

默认的 `combined` 日志格式**不记录 POST 请求体**。没有请求体时：

* 明文工具（蚁剑）还能靠 URL + UA + 固定载荷识别；
* **加密工具（冰蝎、哥斯拉）完全看不到载荷**，检测能力大幅下降。

配置片段已生成在 `/etc/webshell-watch/nginx-request-body.conf`：

```nginx
# 放在 nginx.conf 的 http {} 块里
log_format webshell_detect '$remote_addr - $remote_user [$time_local] '
                           '"$request" $status $body_bytes_sent '
                           '"$http_referer" "$http_user_agent" '
                           '$request_body';

# 在对应 server {} / location {} 里启用
access_log /var/log/nginx/access.log webshell_detect;
```

```bash
nginx -t && systemctl reload nginx
sudo wsp check          # 自检会确认日志源是否带 _body 格式
```

担心日志体积？用同一文件里给出的 `webshell_detect_light`
（只对脚本请求记录请求体，用 `map` 实现）。
注意 `$request_body` 只在请求体被读取后才有值（经过 `proxy_pass` / `fastcgi_pass` 一定有），
纯静态目录一般为空。

**Apache 用户**：把 `%r`、`%{User-Agent}i` 与请求体变量组合成一行，
格式名配 `apache_combined_body`。

---

## 3. Windows 版部署（IIS）

```powershell
# 1) 先看它能不能抓出东西（不需要管理员）
python demo.py

# 2) 环境自检：会告诉你 IIS 日志在哪、事件日志权限够不够、Web 根目录对不对
.\windows\wsp-windows.ps1 check

# 3) 按自检提示修改 windows.json 里的 webroots / iislog.sources

# 4) 前台试运行，看是否抓到告警
.\windows\wsp-windows.ps1 start --foreground

# 5) 以【管理员身份】安装为开机自启（计划任务，SYSTEM 权限，崩溃自动重启）
.\windows\install-service.ps1
```

也可以直接双击 `windows\启动自检.bat`，它会跑自检并给出下一步提示。

Windows 版会写入：

| 路径 | 内容 |
|---|---|
| `C:\ProgramData\webshell-watch\config.json` | 配置（由 `windows.json` 生成） |
| `C:\ProgramData\webshell-watch\logs\alerts-*.jsonl` | 结构化告警（一行一条） |
| `C:\ProgramData\webshell-watch\logs\alerts-*.log` | 人类可读摘要 |
| `C:\ProgramData\webshell-watch\logs\watch-*.log` | 运行日志 |
| `C:\ProgramData\webshell-watch\state\` | 文件基线、事件日志进度、落地目录基线 |
| 计划任务 `webshell-watch` | 开机自启（查看：`.\windows\install-service.ps1 -Status`） |

### Windows 上必须知道的三个前提

1. **Security 事件日志需要管理员权限**。
   非管理员运行时该模块会自动跳过，并在自检与运行日志里明确提示
   （不会静默失效让你误以为一切正常）。安装脚本注册的计划任务以 SYSTEM 身份运行，
   所以正式部署后事件日志是能读的。
2. **IIS 原生日志不记录 POST 请求体**。这意味着冰蝎/哥斯拉这类把载荷放在 body 里的
   加密马，在 Windows 上**主要靠文件巡检与事件日志发现**，而不是靠日志内容。
   工具会在样本量足够后主动告警提示这一能力缺口（`DEF-050`）。
   若想补齐，两条路：
   - 装 IIS **Advanced Logging** 扩展并记录请求体字段；或
   - 在 IIS 前面挂一层 **nginx 反向代理**，由 nginx 记录 `$request_body`，
     再用 `weblog` 配置读 nginx 日志（格式与 Linux 版完全相同）。
3. **PowerShell 脚本块日志（4104）默认可能未开启**，不开则 `DEF-044` 不会触发。
   开启方式（组策略或注册表）：

```powershell
# 以管理员身份执行，开启 PowerShell 脚本块日志
$p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
New-Item -Path $p -Force | Out-Null
Set-ItemProperty -Path $p -Name EnableScriptBlockLogging -Value 1
# 之后 DEF-044 才能从 4104 事件里发现「下载执行」类行为
```

---

## 4. 检测能力

### 4.1 工具特征（请求长什么样）

| 工具 | 关键特征 | 分值 |
|---|---|---|
| **蚁剑** | 默认 UA `antSword/v2.1`；请求体固定载荷段 `QGluaV9zZXQ…`（解码为 `@ini_set("display_errors","0");@set_time_limit(0);`）；默认参数 `z0/z1/z2`；PHP/.NET 动态执行链；响应含 `X@Y` 分隔标记 | 30~70 |
| **冰蝎** | 内置 UA 池（Chrome 89 Mac / Firefox 87 / Chrome 84 固定版本）；默认密钥 `e45e329feb5d925b`；固定请求/响应字节头；`octet-stream` + 超长 Base64；Java 序列化魔数 `rO0AB`、`yv66vg` | 20~70 |
| **哥斯拉** | 响应结构 `16位hex + Base64 + 16位hex`；默认 UA Firefox 84；`Java/1.8`、okhttp 等运行时 UA；Cookie 尾分号；Java 反射链 | 15~65 |
| **扫描器** | nuclei / xray / goby / dirsearch / sqlmap / awvs 等 UA | 35 |

**取证解密**：命中冰蝎默认密钥时会**真的把载荷解开**，告警证据里直接给出明文命令；
蚁剑的 Base64/URL 载荷也会解码成明文 PHP 代码。哥斯拉已知口令时同样可解。

### 4.2 防守行为特征（服务器上发生了什么）

| 规则 | 内容 | 分值 |
|---|---|---|
| DEF-001 | POST 打向脚本文件 + 有载荷体 + 无 Referer（典型马调用） | 25 |
| DEF-002 | 单参数承载 Base64 密文的数据通道形态 | 20 |
| DEF-003/004 | webshell 常见路径命名、对不存在脚本的 POST 探测 | 12~15 |
| DEF-010 | 扫描器/管理工具 UA | 35 |
| DEF-011 | 载荷含 `eval(`、`whoami`、`/etc/passwd`、`../` 等利用特征 | 30 |
| DEF-020 | 同源 IP 高频请求脚本文件（60 秒内 30 次） | 20 |
| DEF-021 | 同一脚本被大量不同 IP 访问（马被批量利用） | 25 |
| DEF-030 | Web 目录**新增**脚本文件 | 30 |
| DEF-031 | 文件内容命中 webshell 特征（一句话马/加密马） | 55+ |
| DEF-032 | 文件内容命中编码/混淆马特征 | 45+ |
| DEF-033 | 脚本权限 777 或属主为 Web 进程用户（**仅 Linux**） | 20 |
| DEF-034 | 脚本文件与基线不一致（被篡改） | 25 |
| DEF-035 | Web 目录出现 `.py/.pl/.sh/.cgi/.war` 等非 Web 脚本 | 30 |
| DEF-036 | **上传/数据目录里出现脚本文件**（IIS 场景重点） | 35 |
| DEF-037 | **Windows 落地目录新增可执行文件**（Temp/Public/ProgramData） | 40 |
| DEF-038 | **web.config / .user.ini / .htaccess 被新增或篡改** | 40 |
| DEF-040 | SSH 爆破 / **Windows 登录失败暴破** | 30 |
| DEF-041 | 登录成功（Linux SSH / **Windows 4624**，来源不在信任列表时提示，爆破后登录加分） | 15 |
| DEF-042 | `sudo` 提权、建号、改密码 / **Windows 4672、4720、4732** | 40 |
| DEF-043 | **Windows 新服务安装（7045，攻击者常用持久化）** | 45 |
| DEF-044 | **PowerShell 脚本块含下载执行/绕过防护（4104）** | 45 |
| DEF-050 | 日志未记录请求体 → 检测能力受限提醒 | 10 |

文件内容特征共 18 条，覆盖：

* **PHP**：`eval($_POST)`、变量函数调用、`base64_decode` 大块数据、`chr()/\xNN` 拼接、
  冰蝎 PHP 结构、`assert($_POST)`、`disable_functions` 绕过、写文件后门
* **JSP**：`ClassLoader#defineClass`、AES 解密型、Java 内存马、反序列化入口
* **ASPX/.NET（Windows）**：`Request[...]` → `Assembly.Load`/`CreateInstance` 链、
  `Eval(Request...)`、`WScript.Shell`、`CSharpCodeProvider` 动态编译、
  `LosFormatter`/`ObjectStateFormatter` ViewState 反序列化 gadget

---

## 5. 告警长什么样

`alerts-YYYYMMDD.jsonl`（每行一条，可直接进 SIEM / 日志平台）：

```json
{"time":"2026-10-13 10:01:40.001","host":"web01","severity":"CRITICAL","severity_cn":"严重",
 "tool":"蚁剑","rule_id":"ANT-020,ANT-001,ANT-090","score":130,
 "title":"User-Agent 暴露蚁剑客户端（antSword/…） ＋ 请求体中包含蚁剑固定初始化载荷（QGluaV9zZXQ…）",
 "flow":"198.51.100.7 -> /upload/shell.php",
 "source":"Web日志(nginx-access)",
 "evidence":"ANT-020: 请求头 user-agent: antSword/v2.1 || ANT-001: 字段[body]命中 QGluaV9zZXQ …",
 "advice":"蚁剑未修改默认 UA，可直接判定为蚁剑管理端流量。请立即定位并处置被控服务器。"}
```

同时会写入：

* `alerts-*.log`：人类可读摘要（Linux 上安装脚本会配 logrotate）
* **syslog**（Linux，facility `local0`）：接入现有日志平台
* **webhook**（可选，`webhook.enabled=true`）：通用 JSON / 钉钉 / 企业微信 / Slack，
  默认只推送 `HIGH` 及以上

去重规则：同一「首个规则 + 判定类型 + 来源」在 300 秒内只报一次
（`notify.dedupe_seconds`），避免高频通信刷爆日志。

---

## 6. 配置说明

* Linux：`/etc/webshell-watch/config.json`（由 `linux.json` 生成）
* Windows：`C:\ProgramData\webshell-watch\config.json`（由 `windows.json` 生成）
* 两份文件**结构完全一致**，只是默认路径不同 —— 因此同一份配置可以在两平台间同步，
  平台专属模块会在另一个平台上自动跳过。

```jsonc
{
  "analyzer": {
    "min_score": 25,          // 告警门槛：调高更少告警。建议先 25~40 观察
    "try_decrypt": true,      // 用默认密钥尝试解密冰蝎载荷（强烈建议开启）
    "passwords": ["rebeyond", "admin", "123456"],  // 派生冰蝎密钥的口令字典
    "disabled_rules": []      // 想关掉的规则 ID
  },
  "weblog": {                 // nginx / apache / tomcat
    "enabled": true,
    "sources": [{"name": "nginx-access", "path": "/var/log/nginx/access.log",
                 "format": "nginx_combined_body"}],
    "from_beginning": false   // false=只看新增（推荐），true=启动时回扫全量
  },
  "iislog": {                 // 仅 Windows
    "enabled": true,
    "sources": [{"name": "iis", "path": "C:\\inetpub\\logs\\LogFiles", "newest_files": 3}]
  },
  "winevent": {               // 仅 Windows，Security 需管理员
    "enabled": true, "log_name": "Security", "fail_threshold": 10,
    "trusted_ips": []
  },
  "windrop": {                // 仅 Windows
    "enabled": true,
    "directories": ["C:\\Windows\\Temp", "C:\\Users\\Public", "C:\\ProgramData"],
    "lookback_days": 7
  },
  "filescan": {
    "enabled": true,
    "webroots": ["/var/www"],                       // Windows: ["C:\\inetpub\\wwwroot"]
    "script_extensions": [".php", ".jsp", ".aspx"],
    "interval": 300,                                 // 巡检间隔（秒）
    "exclude_dirs": ["/var/www/html/wp-content/cache"]
  },
  "authlog": {                // 仅 Linux
    "enabled": true, "fail_threshold": 10,
    "trusted_ips": ["203.0.113.10"]                  // 你的运维跳板机
  },
  "sniff":  { "enabled": false },                    // 仅 Linux，HTTPS 看不到明文
  "output": { "log_dir": "/var/log/webshell-watch", "syslog": true },
  "webhook": { "enabled": false, "url": "", "format": "dingtalk", "min_severity": "HIGH" }
}
```

自定义规则放在规则目录（`/etc/webshell-watch/rules/` 或
`C:\ProgramData\webshell-watch\rules\`），格式见 `rules/custom-rules.json`：
规则 id 与内置规则相同则覆盖内置规则。

可用 kind：`substr` `regex` `header` `param` `entropy` `tls`（请求/流量匹配）、
`log` `stat` `filescan` `filemeta` `policy`（防守侧匹配）。

---

## 7. 命令一览

**两个平台通用**（Windows 上把 `wsp` 换成 `.\windows\wsp-windows.ps1`）：

```bash
wsp start [--foreground] [--once] [--disable sniff]   # 启动（systemd/计划任务就是调它）
wsp check                                    # 环境/权限/日志源/规则/基线 自检
wsp analyze-log /var/log/nginx/access.log --from-beginning   # 离线分析历史日志
wsp filescan [--update-baseline]             # 立刻巡检 / 发布代码后更新基线
wsp analyze-pcap /path/a.pcap                # 分析抓包文件
wsp rules                                    # 列出全部规则
wsp report                                   # 告警统计与最近告警
python3 demo.py                              # 本机演示，确认真能抓出东西
python3 selftest.py                          # 自测（53 项断言）
```

`start --once` 会把所有监控器各跑一轮就退出，用于：

* 安装后确认日志解析与规则链路真的通了
* 放进 cron / 计划任务做低频率巡检
  （Linux：`0 * * * * /usr/local/bin/wsp start --once >/dev/null 2>&1`）

**平台专属安装命令**：

```bash
# Linux
sudo ./install.sh                   # 安装并启动 systemd 服务
sudo ./install.sh --uninstall       # 卸载（保留日志）

# Windows（管理员 PowerShell）
.\windows\install-service.ps1               # 安装开机自启
.\windows\install-service.ps1 -Status       # 查看状态
.\windows\install-service.ps1 -Uninstall    # 卸载
```

**发布代码后请更新基线**，否则正常的文件变更会一直告警：

```bash
sudo wsp filescan --update-baseline            # Linux
.\windows\wsp-windows.ps1 filescan --update-baseline   # Windows
```

---

## 8. 收到告警后怎么处置

完整清单见 **[INCIDENT-RESPONSE.md](INCIDENT-RESPONSE.md)**（含每个平台的具体命令）。
核心流程：**先取证 → 再断链 → 查持久化 → 清理恢复 → 加固**。
按告警证据分三类：

**A. 工具特征告警（蚁剑/冰蝎/哥斯拉 UA、固定载荷、解密出明文命令）**
服务器上确实有马且正在被使用 → 保全证据 → 改名或 `chmod 000` 断链 →
翻日志找最早的上传请求 → 排查持久化 → 轮换凭据。

**B. 文件告警（新增/篡改/权限/上传目录脚本/web.config 篡改）**
可能是正常发布。核对发布记录：不是发布产生的就按 A 处理；
是发布产生的，`wsp filescan --update-baseline` 更新基线。

**C. 认证与行为告警（SSH 爆破、提权、Windows 服务安装、落地 exe）**
多与 A 同时出现 —— 那就是完整攻击链；单独出现也要查：
爆破来源是否成功登录、服务路径是否指向 Temp、落地 exe 的哈希是什么。

---

## 9. 顺手做的加固（比事后检测更有效）

**Linux**

```bash
# 上传目录禁止执行 PHP
#   nginx: location ^~ /uploads/ { location ~ \.php$ { return 403; } }
# 代码属主改 root，去掉 Web 进程写权限
chown -R root:root /var/www && find /var/www -type d -exec chmod 755 {} \; && find /var/www -type f -exec chmod 644 {} \;
# PHP 加固：open_basedir 限定目录、关闭 allow_url_include、禁用危险函数
# 审计关键目录
apt-get install -y auditd && auditctl -w /var/www -p wa -k webroot
```

**Windows**

```powershell
# 1) IIS：关闭上传目录的脚本执行（这是最关键的一条）
#    IIS 管理器 → 站点 → 处理程序映射 → 添加「脚本映射」限制；
#    或在上传目录放一个只含拒绝规则的 web.config：
#      <configuration><system.webServer><handlers>
#        <clear /><add name="BlockAll" path="*" verb="*" type="System.Web.HttpForbiddenHandler" />
#      </handlers></system.webServer></configuration>

# 2) 关闭不必要的 ISAPI/CGI，移除 WebDAV
# 3) Web 根目录权限：IIS_IUSRS 只读，禁止写入
icacls C:\inetpub\wwwroot /grant "IIS_IUSRS:(OI)(CI)RX" /T
icacls C:\inetpub\wwwroot /remove "IIS_IUSRS:(OI)(CI)W" /T

# 4) 开启审计策略（否则很多事件根本不会产生）
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Process Creation" /success:enable
auditpol /set /subcategory:"Account Management" /success:enable /failure:enable

# 5) 定期查落地目录与自启动项
Get-ChildItem C:\Windows\Temp,C:\Users\Public -Recurse -Include *.exe,*.dll,*.ps1 |
  Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) } | Select-Object FullName,LastWriteTime
Get-CimInstance Win32_Service | Where-Object { $_.PathName -match "Temp|Public|ProgramData" } |
  Select-Object Name,PathName,StartMode
```

---

## 10. 能力边界（务必了解）

* **HTTPS 抓包无效（Linux）/ Windows 不提供抓包**：服务器侧是密文，必须依赖访问日志。
  这是本工具以日志为主的原因。
* **Windows 上 IIS 不记录请求体**：加密马主要靠文件巡检、上传目录脚本、
  事件日志与落地目录扫描发现；工具会主动提示这一缺口，不会静默失效。
* **Windows 事件日志需要管理员**：非管理员运行时该模块自动跳过（自检里会说明）。
* **文件权限告警仅 Linux 有效**：Windows 无 Unix 权限位，已自动跳过。
* **加密马只能在口令字典范围内解密**：未知口令只能靠结构特征判定。
* **不能替代主机层检测**：内存马、无文件落地、纯数据库协议通信等场景，
  请看 auditd / ETW / eBPF / 主机 agent；本工具专注 Web 流量与落地文件。
* **告警不等于确认**：所有告警都附带证据与建议，请按第 8 节流程人工确认后再处置。

---

## 11. 项目结构

```
webshell-watch/
├── wsp.py                      命令行实现（两平台共用；平台入口只负责选默认配置）
├── linux.json / windows.json   两平台默认配置（结构一致，仅路径不同）
├── demo.py                     本机演示：造仿真环境，确认工具真能抓出告警
├── selftest.py                 自测：53 项断言（含 Windows 段）
├── install.sh                  Linux 一键安装（systemd + logrotate + nginx 配置片段）
├── INCIDENT-RESPONSE.md        排查与处置清单（两平台命令）
├── rules/custom-rules.json     自定义规则示例
├── linux/
│   └── wsp-linux               Linux 版入口（自动使用 linux.json）
├── windows/
│   ├── wsp-windows.ps1         Windows 版入口（自动使用 windows.json）
│   ├── install-service.ps1     安装/卸载/查看开机自启（计划任务，SYSTEM 权限）
│   └── 启动自检.bat             双击即跑自检
└── wsa/                        共用检测引擎
    ├── daemon.py               守护进程，编排各监控器（按平台启用）
    ├── logs.py                 Web 访问日志监控（nginx/apache，含请求体、轮转跟踪）
    ├── winmon.py               Windows 专属：IIS 日志 / 事件日志 / 落地目录
    ├── authmon.py              Linux 认证日志（SSH 爆破、提权）
    ├── filescan.py             Web 目录巡检（基线 / 内容特征 / 权限 / 上传目录 / web.config）
    ├── packetmon.py            Linux 网卡抓包（AF_PACKET，可选）
    ├── pcapdir.py              pcap 目录监视
    ├── alerting.py             告警输出（JSONL / syslog / webhook / 去重）
    ├── rules_defense.py        防守规则（日志、统计、文件、Windows 事件、配置基线）
    ├── rules_*.py              蚁剑 / 冰蝎 / 哥斯拉 / 通用 特征规则
    ├── analysis.py             检测引擎（打分与定性）
    ├── evidence.py             载荷解密取证（冰蝎 AES / 蚁剑 Base64）
    ├── aes.py                  纯 Python AES-128（FIPS-197 向量校验）
    ├── pcap.py / capture.py / http.py / tls.py / rules.py / models.py / utils.py
    └── selftest_min.py         自检链路（--check 用）
```

---

## 12. 自测与验证

```bash
python3 selftest.py     # 53 项断言，无需 root，两个平台都能跑
python3 demo.py         # 端到端演示，会打印真实告警
python3 lint_check.py   # 语法与导入检查
wsp check               # 部署后的一键体检
```

`selftest.py` 的 53 项断言覆盖：

**通用（Linux 侧为主）**
* 蚁剑/冰蝎/哥斯拉 三类流量在**日志形态**下全部检出；冰蝎默认密钥解密出明文命令
* 扫描器 UA、命令执行载荷、路径穿越、高频访问脚本 均触发对应规则
* **正常浏览器 / 健康检查 / 正常业务 API 零高危告警**
* logrotate（inode 变化）与文件截断后仍能继续跟踪日志
* 5 个 PHP webshell 样本全部命中，正常业务代码零误报
* 新增文件 / 篡改文件 / 更新基线后不再误报
* SSH 爆破、爆破后登录加分、提权与建号
* 未开启请求体日志时给出能力基线提醒

**Windows 侧**
* IIS W3C 表头解析、字段映射（IP/方法/路径/状态/UA）、查询串载荷解码
* IIS 日志中检出蚁剑流量、扫描器 UA、命令执行载荷；正常浏览流量无额外高危
* Windows 事件：登录失败统计、登录成功、提权建号、**服务安装 7045**、
  **PowerShell 高危脚本块 4104**、爆破后登录加分、事件进度可持久化
* **ASPX/.NET webshell 样本全部检出**，正常 ASPX 页面零误报
* 上传目录脚本（DEF-036）、web.config 篡改（DEF-038）
* 落地目录：首次只建基线、新增 exe 告警（DEF-037）、噪声文件名被过滤

---

## 13. 免责声明

本工具用于**自有或已获授权的服务器**的安全监控与应急响应。
安装前请确认你有该主机的管理权限；日志中会包含请求体，请注意日志文件的访问控制与留存合规。

