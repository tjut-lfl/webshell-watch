#!/usr/bin/env python3
"""
wsp —— WebShell 防守监控命令行入口

命令一览：
    wsp start              启动守护监控（systemd 调用，也可手动 nohup 运行）
    wsp check              环境与能力自检（权限、日志路径、规则、基线）
    wsp analyze-log        离线分析已有的访问日志（不需要守护进程）
    wsp filescan           立即执行一次 Web 目录巡检/建立基线
    wsp analyze-pcap       分析 pcap/pcapng 文件或目录
    wsp rules              列出全部规则
    wsp report             显示当前告警文件路径与最近告警统计
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wsa.alerting import Alerter  # noqa: E402
from wsa.analysis import Analyzer  # noqa: E402
from wsa.config import WatchConfig, load_config  # noqa: E402
from wsa.filescan import FileScanner  # noqa: E402
from wsa.logs import WebLogMonitor  # noqa: E402
from wsa.models import Severity  # noqa: E402

__version__ = "1.0.0"

BANNER = r"""
 __      __ ___  ___    _     _       _       _
 \ \    / / __|/ __|  /_\   | | | | __| |__ __| |_  WebShell 防守监控
  \ \/\/ /\__ \ (_ | / _ \  | |_| |/ _| / _| '_ \| 服务器侧 webshell 流量与痕迹检测
   \_/\_/ |___/\___|/_/ \_\  \__,_|\__|_\__|_|_|_|_| v{version}
""".strip("\n")


# ============================================================================
# 平台默认值：两个平台版本通过环境变量注入各自的默认配置路径，
# 因此 linux/wsp-linux.py 与 windows/wsp-windows.ps1 可以共用这一份实现。
# ============================================================================
DEFAULT_CONFIG_PATH = os.environ.get("WW_CONFIG") or ""


def _prepare_argv(argv: Optional[List[str]]) -> List[str]:
    """
    若调用方没有显式指定 --config/-c，则补上平台默认配置路径。

    这样做的目的：两个平台的入口只负责「选择自己那份默认配置」，
    校验、自检、规则加载等逻辑完全共用，避免出现两份实现逐渐不一致的问题。
    """
    args = list(sys.argv[1:] if argv is None else argv)
    if not DEFAULT_CONFIG_PATH:
        return args
    if any(arg in ("--config", "-c") or arg.startswith("--config=")
           or (arg.startswith("-c") and len(arg) > 2) for arg in args):
        return args
    return ["--config", DEFAULT_CONFIG_PATH] + args


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="wsp",
        description="WebShell 防守监控：在服务器上发现蚁剑/冰蝎/哥斯拉等管理工具的流量与落地痕迹",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "示例：\n"
            "  sudo wsp start                      # 启动守护监控（推荐交给 systemd）\n"
            "  sudo wsp start --foreground         # 前台运行，日志直接打印到终端\n"
            "  sudo wsp check                      # 自检：权限、日志、规则、基线\n"
            "  sudo wsp analyze-log /var/log/nginx/access.log --from-beginning\n"
            "  sudo wsp filescan --update-baseline # 发布代码后更新文件基线\n"
            "  wsp rules                           # 查看全部规则\n"
        ),
    )
    p.add_argument("--config", "-c", default="/etc/webshell-watch/config.json",
                   help="配置文件路径。Linux 版默认 /etc/webshell-watch/config.json；"
                        "Windows 版入口会自动换成 windows.json（或在 ProgramData 下生成的配置）")
    p.add_argument("--version", action="version", version=f"wsp {__version__}")
    sub = p.add_subparsers(dest="command")

    # start
    sp = sub.add_parser("start", help="启动守护监控")
    sp.add_argument("--foreground", "-f", action="store_true", help="前台运行并打印日志")
    sp.add_argument("--once", action="store_true",
                    help="只跑一轮巡检就退出（部署后验证 / cron 巡检用）")
    sp.add_argument("--disable", action="append", default=[], metavar="模块",
                    help="临时关闭某个监控器：weblog/authlog/filescan/sniff/pcap")

    # check
    sub.add_parser("check", help="环境与能力自检")

    # analyze-log
    lp = sub.add_parser("analyze-log", help="离线分析访问日志")
    lp.add_argument("path", nargs="+", help="日志文件路径")
    lp.add_argument("--format", default="", help="日志格式名（默认自动识别）")
    lp.add_argument("--from-beginning", action="store_true", help="从头分析（默认只看新增）")
    lp.add_argument("--min-score", type=int, default=0, help="告警最低分值")
    lp.add_argument("--export", default="", help="把告警额外导出到指定 JSONL 文件")
    lp.add_argument("--quiet", "-q", action="store_true", help="只打印统计，不打印每条告警")

    # filescan
    fp = sub.add_parser("filescan", help="执行一次 Web 目录巡检")
    fp.add_argument("--webroot", action="append", default=[], help="覆盖配置里的 Web 目录")
    fp.add_argument("--update-baseline", action="store_true", help="重建基线（发布代码后使用）")
    fp.add_argument("--min-score", type=int, default=0)

    # analyze-pcap
    pp = sub.add_parser("analyze-pcap", help="分析抓包文件或目录")
    pp.add_argument("path", nargs="+", help="pcap/pcapng 文件或目录")
    pp.add_argument("--min-score", type=int, default=0)

    # rules
    sub.add_parser("rules", help="列出全部规则")

    # report
    sub.add_parser("report", help="显示告警文件与最近统计")
    return p


# ---------------------------------------------------------------------------
def make_alerter(cfg: WatchConfig, console: bool = False, quiet: bool = False) -> Alerter:
    out = cfg.section("output")
    return Alerter(
        log_dir=cfg.log_dir,
        save_jsonl=bool(out.get("save_jsonl", True)),
        syslog=False if quiet else bool(out.get("syslog", True)),
        syslog_facility=str(out.get("syslog_facility", "local0")),
        console=console and not quiet,
        color=bool(out.get("color", True)),
        verbose=not quiet,
        hostname=cfg.hostname,
        dedupe_seconds=int(cfg.section("notify").get("dedupe_seconds", 300)),
        webhook=cfg.section("webhook") if not quiet else {},
        state_dir=cfg.state_dir,
    )


def make_analyzer(cfg: WatchConfig, min_score: int = 0) -> Analyzer:
    opts = cfg.analysis_options()
    if min_score:
        opts.min_score = int(min_score)
    return Analyzer(
        rule_dir=cfg.rule_dir,
        options=opts,
        disabled_rules=cfg.disabled_rules(),
        enabled_tools=cfg.enabled_tools(),
    )


# ---------------------------------------------------------------------------
def _euid() -> int:
    """有效 uid；Windows 上不适用，返回 -1。"""
    getter = getattr(os, "geteuid", None)
    return getter() if callable(getter) else -1


def _platform_name() -> str:
    from wsa.daemon import _platform_name as impl

    return impl()


def cmd_start(cfg: WatchConfig, args) -> int:
    disabled = {x.lower() for x in (args.disable or [])}
    for name in disabled:
        section = {"weblog": "weblog", "authlog": "authlog", "filescan": "filescan",
                   "sniff": "sniff", "pcap": "pcap"}.get(name)
        if section:
            cfg.raw.setdefault(section, {})["enabled"] = False
    if _euid() not in (0, -1):
        print("[提示] 当前不是 root，可能读不到 /var/log/nginx、/var/log/auth.log，"
              "文件巡检也可能不完整。建议 sudo 运行或交给 systemd。")
    # 前台运行与单次巡检都需要把日志打到终端
    if args.foreground or args.once:
        cfg.raw.setdefault("output", {})["console"] = True
    from wsa.daemon import WatchDaemon

    daemon = WatchDaemon(cfg)
    if args.once:
        return daemon.run_once()
    return daemon.start()


def cmd_check(cfg: WatchConfig, args) -> int:
    print(BANNER.format(version=__version__))
    print("=" * 74)
    print("环境与能力自检")
    print("=" * 74)
    print(f"运行平台      : {_platform_name()}")
    print(f"主机名        : {cfg.hostname}")
    print(f"Python        : {sys.version.split()[0]}")
    print(f"配置文件      : {cfg.source_path or '（使用内置默认值）'}")
    euid = _euid()
    if euid == 0:
        id_text = "uid=0（root，权限充分）"
    elif euid < 0:
        id_text = "Windows（无 Unix uid 概念，见下方事件日志权限）"
    else:
        id_text = f"uid={euid}（非 root，可能读不到 /var/log 下的日志）"
    print(f"运行身份      : {id_text}")

    analyzer = make_analyzer(cfg)
    tools: dict = {}
    for r in analyzer.rules:
        tools[r.tool] = tools.get(r.tool, 0) + 1
    print(f"规则总数      : {len(analyzer.rules)} 条（{'、'.join(f'{k} {v}' for k, v in tools.items())}）")

    print("\n--- 访问日志源 ---")
    if os.name == "nt":
        _check_windows_sources(cfg, analyzer)
    else:
        _check_linux_sources(cfg)

    print("\n--- Web 目录巡检 ---")
    fs = cfg.section("filescan")
    for root in (fs.get("webroots") or []):
        print(f"  {root}\n      状态：{_path_status(root)}")
    scanner = FileScanner(
        alert_fn=lambda a: None,
        log_fn=lambda lvl, msg: None,
        rules=analyzer.rules,
        webroots=fs.get("webroots") or [],
        script_extensions=fs.get("script_extensions") or [],
        state_dir=cfg.state_dir,
        exclude_dirs=fs.get("exclude_dirs") or [],
    )
    base_state = "已存在" if not scanner.baseline_missing else "不存在（首次巡检时会自动建立）"
    print(f"  文件基线      : {scanner.baseline_path}（{base_state}）")

    if os.name != "nt":
        print("\n--- 抓包能力 ---")
        has_af = hasattr(__import__("socket"), "AF_PACKET")
        cap = "可用" if (has_af and euid == 0) else ("需要 root" if has_af else "当前平台不支持")
        print(f"  AF_PACKET 抓包: {cap}（配置里 sniff.enabled={cfg.section('sniff').get('enabled')}）")
        print("  说明：抓包只能看到明文 HTTP 与 TLS 指纹；HTTPS 明文请依赖访问日志。")

    print("\n--- 输出 ---")
    probe = Alerter(
        log_dir=cfg.log_dir, save_jsonl=False, syslog=False, console=False, hostname=cfg.hostname
    )
    for name, path in probe.paths.items():
        print(f"  {name}: {path}")
    print(f"  日志目录可写  : {'是' if os.access(cfg.log_dir, os.W_OK) else '否（服务运行时会自动创建）'}")

    print("\n--- 检测链路自检 ---")
    ok, detail = _link_selftest(analyzer, cfg)
    print(f"  {'通过' if ok else '失败'} —— {detail}")
    print("\n自检完成。")
    return 0 if ok else 1


def _check_linux_sources(cfg: WatchConfig, analyzer: Analyzer) -> None:
    from wsa.logs import WebLogMonitor  # noqa: F401

    wl = cfg.section("weblog")
    body_hint = False
    for src in (wl.get("sources") or []):
        path = str(src.get("path", ""))
        fmt = str(src.get("format", ""))
        print(f"  [{src.get('name', '-')}] {path}\n      状态：{_path_status(path)}  格式：{fmt or '自动识别'}")
        if "body" in fmt:
            body_hint = True
    if not body_hint:
        print("  [注意] 没有任何日志源配置了带请求体的格式（*_body）。")
        print("         没有请求体时，冰蝎/哥斯拉这类加密马的载荷无法被检测。")
        print("         请在 nginx 中开启 $request_body 记录（见 README 第 3 节）。")

    print("\n--- 认证日志 ---")
    for src in (cfg.section("authlog").get("sources") or []):
        path = str(src.get("path", ""))
        print(f"  [{src.get('name', '-')}] {path}\n      状态：{_path_status(path)}")


def _check_windows_sources(cfg: WatchConfig, analyzer: Analyzer) -> None:
    """Windows 侧的能力自检：IIS 日志、事件日志、落地目录。"""
    iis = cfg.section("iislog")
    print("  IIS 日志源：")
    found_any = False
    for src in (iis.get("sources") or []):
        path = str(src.get("path", ""))
        if os.path.isdir(path):
            logs = []
            try:
                logs = sorted(
                    f for f in os.listdir(path) if f.lower().endswith(".log")
                )
            except OSError:
                pass
            print(f"    [{src.get('name', '-')}] {path}（目录，{len(logs)} 个日志文件）")
            if logs:
                print(f"      最新：{logs[-1]}")
                _probe_iis_file(os.path.join(path, logs[-1]))
            found_any = True
        elif os.path.isfile(path):
            print(f"    [{src.get('name', '-')}] {path}  状态：{_path_status(path)}")
            _probe_iis_file(path)
            found_any = True
        else:
            print(f"    [{src.get('name', '-')}] {path}  状态：不存在（若未使用 IIS 可忽略）")
    if not found_any:
        print("    未找到任何 IIS 日志。若你的 Web 服务是 IIS，请确认站点已开启日志。")
    print("      提示：IIS 原生日志不记录 POST 请求体，加密马只能靠文件巡检与事件日志发现。")

    print("\n  其他 Web 日志（nginx/apache/tomcat，格式按 weblog 配置）：")
    wl = cfg.section("weblog")
    for src in (wl.get("sources") or []):
        path = str(src.get("path", ""))
        if os.name == "nt" and not str(path).lower().startswith(("c:", "d:", "e:")):
            continue    # 非 Windows 路径，跳过
        print(f"    [{src.get('name', '-')}] {path}  状态：{_path_status(path)}")

    print("\n  文件巡检目录与模块：")
    fs = cfg.section("filescan")
    for root in (fs.get("webroots") or []):
        if os.name == "nt" and not str(root).lower().startswith(("c:", "d:", "e:")):
            continue
        print(f"    {root}  状态：{_path_status(root)}")

    print("\n  Windows 事件日志：")
    try:
        from wsa.winmon import EventLogMonitor

        we = cfg.section("winevent")
        mon = EventLogMonitor(
            alert_fn=lambda a: None,
            log_fn=lambda lvl, msg: None,
            rules=analyzer.rules,
            log_name=str(we.get("log_name", "Security")),
            event_ids=we.get("event_ids") or (),
            state_dir=cfg.state_dir,
        )
        ok, reason = mon.check_available()
        print(f"    {we.get('log_name', 'Security')} 日志：{'可读' if ok else reason}")
    except Exception as exc:
        print(f"    检测失败：{type(exc).__name__}: {exc}")

    print("\n  Windows 落地目录监控：")
    wd = cfg.section("windrop")
    for d in (wd.get("directories") or []):
        print(f"    {d}  状态：{_path_status(d)}")
    print("      说明：这些目录出现新的可执行文件时会告警（首次扫描只建基线）。")


def _probe_iis_file(path: str) -> None:
    """读一个 IIS 日志文件的前几行，确认 #Fields 表头可解析。"""
    try:
        from wsa.winmon import parse_iis_header

        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for _ in range(20):
                line = fh.readline()
                if not line:
                    break
                fields = parse_iis_header(line)
                if fields:
                    print(f"      表头字段：{', '.join(fields)}")
                    return
        print("      未找到 #Fields 表头（该文件可能不是 IIS W3C 格式）")
    except OSError as exc:
        print(f"      读取失败：{exc}")


def _path_status(path: str) -> str:
    if not path:
        return "未配置"
    if os.path.isdir(path):
        return "目录存在" + ("" if os.access(path, os.R_OK) else "（不可读）")
    if os.path.isfile(path):
        return ("可读" if os.access(path, os.R_OK) else "存在但不可读") + f"，{os.path.getsize(path)} 字节"
    return "不存在"


def _link_selftest(analyzer: Analyzer, cfg: WatchConfig) -> tuple[bool, str]:
    """用一段合成的蚁剑日志验证：日志解析 -> 规则 -> 告警 是否通畅。"""
    from wsa.logs import parse_line

    sample = (
        '10.0.0.66 - - [13/Oct/2026:12:00:01 +0800] "POST /upload/shell.php HTTP/1.1" 200 32 '
        '"-" "antSword/v2.1" z0=QGluaV9zZXQoImRpc3BsYXlfZXJyb3JzIiwiMCIpO0BzZXRfdGltZV9saW1pdCgwKTs%3D'
    )
    entry = parse_line(sample)
    if entry is None:
        return False, "合成日志解析失败（解析器异常）"
    txn = entry.to_transaction()
    from wsa.models import Flow, FlowKey, Source

    flow = Flow(key=FlowKey(entry.client_ip, 0, "localhost", 80), source=Source.UNKNOWN)
    flow.transactions = [txn]
    flow.first_ts = flow.last_ts = txn.ts
    alerts = analyzer.analyze_flow(flow)
    if not alerts:
        return False, "合成蚁剑日志未触发告警，请检查规则是否被禁用或分值阈值过高"
    tools = "、".join(sorted({a.tool for a in alerts}))
    return True, f"合成蚁剑日志命中 {len(alerts)} 条告警（{tools}，最高 {max(a.score for a in alerts)} 分）"


def cmd_analyze_log(cfg: WatchConfig, args) -> int:
    alerter = make_alerter(cfg, console=not args.quiet, quiet=args.quiet)
    analyzer = make_analyzer(cfg, args.min_score)
    sources = [
        {"name": f"file:{os.path.basename(p)}", "path": p, "format": args.format}
        for p in args.path
    ]
    mon = WebLogMonitor(
        alert_fn=alerter.emit,
        log_fn=alerter.log,
        analyzer=analyzer,
        sources=sources,
        from_beginning=bool(args.from_beginning),
        final_lines=True,
    )
    print(f"开始分析 {len(sources)} 个日志文件" + ("（从头读取）" if args.from_beginning else "（只看新增内容）"))
    rounds = 0
    while True:
        processed = mon.poll_once()
        rounds += 1
        if processed == 0:
            break
        if rounds > 1000:
            break
    # 需要读全量时，max_line 已读到 EOF；再补一轮确保末尾行处理完
    mon.poll_once()
    print()
    print("=" * 74)
    print(mon.summary())
    print(alerter.summary())
    print("=" * 74)
    for name, path in alerter.paths.items():
        print(f"{name}: {path}")
    if args.export and alerter.alerts:
        alerter.export(args.export)
        print(f"已导出 {len(alerter.alerts)} 条告警到 {args.export}")
    return 0 if not alerter.alerts else 2


def cmd_filescan(cfg: WatchConfig, args) -> int:
    alerter = make_alerter(cfg, console=True)
    analyzer = make_analyzer(cfg, args.min_score)
    fs = cfg.section("filescan")
    roots = args.webroot or fs.get("webroots") or []
    if not roots:
        print("[错误] 没有配置 Web 目录（filescan.webroots 或 --webroot）")
        return 1
    scanner = FileScanner(
        alert_fn=alerter.emit,
        log_fn=alerter.log,
        rules=analyzer.rules,
        webroots=roots,
        script_extensions=fs.get("script_extensions") or [],
        state_dir=cfg.state_dir,
        exclude_dirs=fs.get("exclude_dirs") or [],
        max_file_bytes=int(fs.get("max_file_bytes", 2097152)),
    )
    if args.update_baseline:
        scanner.update_baseline()
        print("已更新文件基线。")
        return 0
    result = scanner.scan()
    print()
    print(result.summary())
    print(alerter.summary())
    if result.unreadable:
        print(f"不可读文件 {len(result.unreadable)} 个，例如：{'、'.join(result.unreadable[:5])}")
    return 0 if not alerter.alerts else 2


def cmd_analyze_pcap(cfg: WatchConfig, args) -> int:
    from wsa.pcapdir import PcapDirMonitor

    alerter = make_alerter(cfg, console=True)
    analyzer = make_analyzer(cfg, args.min_score)
    mon = PcapDirMonitor(
        alert_fn=alerter.emit, log_fn=alerter.log, analyzer=analyzer, directory="/tmp"
    )
    # 直接复用单文件分析逻辑
    from wsa.pcap import sniff_files

    files, skipped = sniff_files(args.path)
    for s in skipped:
        alerter.log("WARN", f"跳过：{s}")
    if not files:
        print("[错误] 没有找到可分析的 pcap/pcapng 文件")
        return 1
    total = 0
    for path in files:
        total += mon.analyze_file(path)
    print()
    print(f"分析完成：{len(files)} 个文件，共 {total} 条告警")
    print(alerter.summary())
    return 0 if total == 0 else 2


def cmd_rules(cfg: WatchConfig, args) -> int:
    analyzer = make_analyzer(cfg)
    groups: dict = {}
    for r in analyzer.rules:
        groups.setdefault(r.tool, []).append(r)
    print(f"共载入 {len(analyzer.rules)} 条规则\n")
    for tool, items in groups.items():
        print(f"[{tool}] {len(items)} 条")
        for r in sorted(items, key=lambda x: -x.score):
            print(f"  {r.id:<9} {r.score:>3} 分  ({r.kind})  {r.title}")
        print()
    return 0


def cmd_report(cfg: WatchConfig, args) -> int:
    log_dir = cfg.log_dir
    print(f"日志目录：{log_dir}")
    if not os.path.isdir(log_dir):
        print("（目录不存在，说明还没运行过）")
        return 0
    files = sorted(os.listdir(log_dir))
    for f in files:
        full = os.path.join(log_dir, f)
        print(f"  {f}  {os.path.getsize(full)} 字节")
    # 统计最近一个 JSONL
    jsonls = [f for f in files if f.startswith("alerts-") and f.endswith(".jsonl")]
    if not jsonls:
        print("暂无告警文件")
        return 0
    path = os.path.join(log_dir, jsonls[-1])
    counts: dict = {}
    tools: dict = {}
    total = 0
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            total += 1
            counts[d.get("severity", "?")] = counts.get(d.get("severity", "?"), 0) + 1
            tools[d.get("tool", "?")] = tools.get(d.get("tool", "?"), 0) + 1
    print(f"\n{jsonls[-1]} 共 {total} 条告警")
    for sev in reversed(Severity.ORDER):
        if counts.get(sev):
            print(f"  {sev:<9} {counts[sev]}")
    if tools:
        print("  按类型：" + "、".join(f"{k} {v}" for k, v in sorted(tools.items(), key=lambda x: -x[1])))
    print("\n最近 10 条：")
    with open(path, "r", encoding="utf-8") as fh:
        lines = fh.readlines()[-10:]
    for line in lines:
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue
        print(f"  [{d.get('severity')}] {d.get('tool')} {d.get('rule_id')} | {d.get('flow')} | {d.get('title')}")
    return 0


# ---------------------------------------------------------------------------
def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(_prepare_argv(argv))
    cfg, notes = load_config(args.config)
    if not args.command:
        parser.print_help()
        return 0

    if args.command == "check":
        # 自检时把提示也打印出来
        for n in notes:
            print(f"[配置] {n}")
        return cmd_check(cfg, args)

    handlers = {
        "start": cmd_start,
        "analyze-log": cmd_analyze_log,
        "filescan": cmd_filescan,
        "analyze-pcap": cmd_analyze_pcap,
        "rules": cmd_rules,
        "report": cmd_report,
    }
    handler = handlers.get(args.command)
    if handler is None:
        parser.print_help()
        return 1
    if args.command in ("analyze-log", "filescan", "analyze-pcap"):
        for n in notes:
            print(f"[配置] {n}")
    return handler(cfg, args)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n已中断。")
        sys.exit(130)
