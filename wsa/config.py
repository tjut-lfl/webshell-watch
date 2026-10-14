"""
防守端配置装载。

配置文件为 JSON（Ubuntu 24.04 自带 Python 无 PyYAML，因此不依赖 YAML）。
默认路径 /etc/webshell-watch/config.json，可用 --config 覆盖。
所有字段都有内置默认值，缺项不影响启动。
"""

from __future__ import annotations

import json
import os
import socket
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .analysis import AnalysisOptions
from .evidence import DEFAULT_PASSWORDS

DEFAULT_CONFIG: Dict[str, Any] = {
    "analyzer": {
        # 告警最低分值：分值越高告警越少。防守端建议 25~40 起步。
        "min_score": 25,
        "try_decrypt": True,
        "passwords": list(DEFAULT_PASSWORDS),
        "max_body_scan": 65536,
        "disabled_rules": [],
        "enabled_tools": ["蚁剑", "冰蝎", "哥斯拉", "加密隧道", "通用WebShell", "防守告警"],
    },
    "weblog": {
        "enabled": True,
        # 每个日志源独立配置；文件不存在时会被跳过并在日志里提示
        "sources": [
            {
                "name": "nginx-access",
                "path": "/var/log/nginx/access.log",
                "format": "nginx_combined_body",
            },
            {
                "name": "apache-access",
                "path": "/var/log/apache2/access.log",
                "format": "apache_combined_body",
            },
        ],
        "from_beginning": False,      # false=只看新增内容（推荐）；true=启动时回扫全量
        "max_line_bytes": 262144,     # 单行日志最大长度，超过则截断
        "untrusted_referer": True,
        "body_truncated_marker": "....",
    },
    "filescan": {
        "enabled": True,
        "webroots": ["/var/www"],
        "script_extensions": [
            ".php", ".php3", ".php4", ".php5", ".php7", ".phtml", ".phar",
            ".jsp", ".jspx", ".jspf", ".asp", ".aspx", ".ashx", ".asmx",
            ".cgi", ".pl", ".py", ".sh", ".war",
        ],
        "interval": 300,               # 巡检间隔（秒）
        "max_file_bytes": 2097152,     # 单文件最多读取多少字节做特征扫描
        "follow_symlinks": False,
        "exclude_dirs": [
            "/var/www/html/wp-content/cache", "/var/www/html/wp-content/uploads",
            "/node_modules", "/.git", "/vendor/cache",
        ],
        "baseline_report": True,       # 首次巡检只建基线并报告可疑文件
    },
    "authlog": {
        "enabled": True,
        "sources": [
            {"name": "auth", "path": "/var/log/auth.log"},
            {"name": "secure", "path": "/var/log/secure"},
        ],
        "from_beginning": False,
        "fail_window": 300,            # 统计窗口（秒）
        "fail_threshold": 10,          # 同源失败次数阈值
    },
    "sniff": {
        "enabled": False,              # 抓包看不了 HTTPS 明文，默认关闭
        "interface": "any",
        "bpf_filter": "tcp",           # 仅支持 tcp / tcp port N 这类简单过滤
        "idle_flush": 20.0,
        "snap_length": 65535,
        "max_flows": 20000,
    },
    # ------------------------------------------------------------------
    # Windows 专属模块（Linux 上会被自动跳过）
    # ------------------------------------------------------------------
    "iislog": {
        "enabled": True,
        # path 可以是单个日志文件，也可以是 IIS 日志目录（按天滚动）
        "sources": [
            {"name": "iis-default", "path": r"C:\inetpub\logs\LogFiles", "newest_files": 3},
        ],
        "from_beginning": False,
        "max_line_bytes": 262144,
    },
    "winevent": {
        "enabled": True,
        "log_name": "Security",
        # 留空表示使用内置默认事件集（4624/4625/4672/4720/4732/7045 等）
        "event_ids": [],
        "max_events": 200,
        "fail_window": 300,
        "fail_threshold": 10,
        "trusted_ips": [],
        "use_whoami_filter": True,
    },
    "windrop": {
        "enabled": True,
        "directories": [
            r"C:\Windows\Temp",
            r"C:\Users\Public",
            r"C:\ProgramData",
            r"C:\Windows\Tasks",
            r"C:\Windows\System32\Tasks",
        ],
        "lookback_days": 7,
        "max_files": 20000,
    },
    "pcap": {
        "enabled": False,
        "watch_dir": "/var/lib/webshell-watch/pcap",
        "interval": 10,
        "settle_seconds": 3,
    },
    "output": {
        "log_dir": "/var/log/webshell-watch",
        "save_jsonl": True,
        "syslog": True,                # 同时写入 syslog（便于接入现有 SIEM）
        "syslog_facility": "local0",
        "console": False,
        "color": True,
        "verbose": True,
        "max_history": 5000,          # 守护进程内存保留条数；0 表示不限制，磁盘日志不受影响
    },
    "webhook": {
        "enabled": False,
        "url": "",                      # 钉钉/企业微信/Slack/飞书 通用 JSON POST
        "format": "generic",            # generic | dingtalk | wecom | slack
        "min_severity": "HIGH",         # 只有达到该级别才推送
        "timeout": 5,
        "headers": {},
    },
    "notify": {
        "min_severity_console": "LOW",
        "dedupe_seconds": 300,          # 同规则+同来源的重复告警去重窗口
    },
    "runtime": {
        "pid_file": "/run/webshell-watch.pid",
        "state_dir": "/var/lib/webshell-watch",
        "status_interval": 60,          # 状态汇总输出间隔（秒）
        "run_as_user": "",              # 留空表示不切换用户（systemd 里已配置）
    },
    "rules": {
        "rule_dir": "",                 # 自定义规则目录（*.json），留空表示只用内置
    },
}


def _deep_merge(base: Dict[str, Any], extra: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(base)
    for k, v in (extra or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


@dataclass
class WatchConfig:
    raw: Dict[str, Any] = field(default_factory=lambda: json.loads(json.dumps(DEFAULT_CONFIG)))
    source_path: str = ""

    def section(self, name: str) -> Dict[str, Any]:
        return self.raw.get(name, {}) or {}

    # -- 便捷访问 ---------------------------------------------------------
    @property
    def hostname(self) -> str:
        try:
            return socket.gethostname()
        except OSError:
            return "unknown-host"

    def analysis_options(self) -> AnalysisOptions:
        a = self.section("analyzer")
        return AnalysisOptions(
            min_score=int(a.get("min_score", 25)),
            try_decrypt=bool(a.get("try_decrypt", True)),
            passwords=[str(p) for p in (a.get("passwords") or DEFAULT_PASSWORDS)],
            max_body_scan=int(a.get("max_body_scan", 65536)),
        )

    def disabled_rules(self) -> List[str]:
        return [str(x) for x in (self.section("analyzer").get("disabled_rules") or [])]

    def enabled_tools(self) -> Optional[List[str]]:
        tools = [str(x) for x in (self.section("analyzer").get("enabled_tools") or [])]
        return tools or None

    @property
    def log_dir(self) -> str:
        return str(self.section("output").get("log_dir", "/var/log/webshell-watch"))

    @property
    def state_dir(self) -> str:
        return str(self.section("runtime").get("state_dir", "/var/lib/webshell-watch"))

    @property
    def pid_file(self) -> str:
        return str(self.section("runtime").get("pid_file", "/run/webshell-watch.pid"))

    @property
    def rule_dir(self) -> str:
        return str(self.section("rules").get("rule_dir", "") or "")


def load_config(path: str = "") -> tuple[WatchConfig, List[str]]:
    """载入配置，返回 (配置, 提示信息)。文件不存在时使用内置默认值。"""
    notes: List[str] = []
    cfg = WatchConfig()
    candidates = [path] if path else [
        "/etc/webshell-watch/config.json",
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config.json"),
    ]
    for cand in candidates:
        if not cand or not os.path.isfile(cand):
            continue
        try:
            with open(cand, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            notes.append(f"配置文件 {cand} 解析失败：{exc}")
            continue
        if not isinstance(data, dict):
            notes.append(f"配置文件 {cand} 不是 JSON 对象，已忽略")
            continue
        cfg.raw = _deep_merge(cfg.raw, data)
        cfg.source_path = cand
        notes.append(f"已载入配置 {cand}")
        break
    else:
        notes.append("未找到配置文件，使用内置默认值")
    return cfg, notes


def write_default_config(path: str, force: bool = False) -> str:
    """生成一份带注释说明的默认配置（安装脚本用）。"""
    if os.path.exists(path) and not force:
        return path
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(DEFAULT_CONFIG, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    return path
