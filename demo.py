#!/usr/bin/env python3
"""
演示脚本：在本机构造一套「已经被 webshell 控制」的仿真环境，
跑一遍完整检测链路并把告警打印出来，用来确认工具在你的机器上真的能工作。

    python3 demo.py            （Windows / Linux 都可以跑，不需要 root）

它会临时创建：
    demo-output/iis/u_ex260113.log     仿真的 IIS 访问日志（含蚁剑调用、扫描器探测）
    demo-output/nginx/access.log       仿真的 nginx 访问日志（含冰蝎加密载荷、哥斯拉）
    demo-output/www-win/…              IIS 站点目录（含 ASPX 一句话马、上传目录里的马、被改的 web.config）
    demo-output/www/…                  Linux 站点目录（含 PHP 一句话马、冰蝎马）
    demo-output/auth.log               仿真的 auth.log（SSH 爆破 + 提权 + 建号）
    demo-output/drop/inject.exe        仿真「工具落地」文件

跑完后会上报告警统计，并告诉你每一类告警对应哪个真实文件的哪一行。
"""

from __future__ import annotations

import base64
import hashlib
import os
import shutil
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from selftest import (
    ANTSWORD_INIT,
    BEHINDER_KEY,
    IIS_LOG,
    WIN_EVENTS,
    _aes128_ecb_encrypt,
    build_access_log,
    build_auth_log,
    build_webroot,
    build_windows_webroot,
)
from wsa.alerting import Alerter
from wsa.analysis import AnalysisOptions, Analyzer
from wsa.authmon import AuthMonitor
from wsa.filescan import FileScanner
from wsa.logs import WebLogMonitor
from wsa.models import Alert, Severity
from wsa.winmon import EventLogMonitor, IisLogMonitor, WindowsDropScanner

WORK = os.path.join(os.path.dirname(os.path.abspath(__file__)), "demo-output")


def hr(title: str = "") -> None:
    print()
    if title:
        print("=" * 78)
        print(title)
        print("=" * 78)
    else:
        print("-" * 78)


def prepare() -> dict:
    """构造仿真环境，返回各路径。"""
    shutil.rmtree(WORK, ignore_errors=True)
    paths = {
        "iis_log": os.path.join(WORK, "iis", "u_ex260113.log"),
        "nginx_log": os.path.join(WORK, "nginx", "access.log"),
        "auth_log": os.path.join(WORK, "auth.log"),
        "www_win": os.path.join(WORK, "www-win"),
        "www_lin": os.path.join(WORK, "www"),
        "drop": os.path.join(WORK, "drop"),
        "state": os.path.join(WORK, "state"),
        "logs": os.path.join(WORK, "logs"),
    }
    for key in ("iis_log", "nginx_log", "auth_log"):
        os.makedirs(os.path.dirname(paths[key]), exist_ok=True)
    for key in ("drop", "state", "logs"):
        os.makedirs(paths[key], exist_ok=True)

    # 1) IIS 日志
    with open(paths["iis_log"], "w", encoding="utf-8") as fh:
        fh.write(IIS_LOG)
    # 2) nginx 日志
    with open(paths["nginx_log"], "w", encoding="utf-8") as fh:
        fh.write("\n".join(build_access_log()) + "\n")
    # 3) auth.log
    with open(paths["auth_log"], "w", encoding="utf-8") as fh:
        fh.write("\n".join(build_auth_log()) + "\n")
    # 4) 两套站点目录
    build_windows_webroot(paths["www_win"])
    build_webroot(paths["www_lin"])
    # 5) 落地文件
    loader = os.path.join(paths["drop"], "inject.exe")
    with open(loader, "wb") as fh:
        fh.write(b"MZ" + os.urandom(2048))
    os.utime(loader, None)
    return paths


def main() -> int:
    print("=" * 78)
    print("WebShell 防守监控 —— 本机演示")
    print("=" * 78)
    print("本演示只在本机临时目录里创建文件，不连接网络、不修改系统配置。")

    hr("第 0 步：构造仿真环境")
    paths = prepare()
    for name, path in paths.items():
        if os.path.isdir(path):
            count = sum(len(f) for _r, _d, f in os.walk(path))
            print(f"  {name:<10} 目录  {path}（{count} 个文件）")
        elif os.path.isfile(path):
            print(f"  {name:<10} 文件  {path}（{os.path.getsize(path)} 字节）")
        else:
            print(f"  {name:<10} 待创建  {path}")

    analyzer = Analyzer(rule_dir="", options=AnalysisOptions(min_score=25))
    alerter = Alerter(log_dir=paths["logs"], syslog=False, console=False, hostname="demo-host")
    print(f"\n  已载入 {len(analyzer.rules)} 条规则")

    # ------------------------------------------------------------------
    hr("第 1 步：分析 nginx 访问日志（明文载荷 + 加密载荷）")
    mon = WebLogMonitor(
        alert_fn=alerter.emit,
        log_fn=alerter.log,
        analyzer=analyzer,
        sources=[{"name": "demo-nginx", "path": paths["nginx_log"], "format": "nginx_combined_body"}],
        from_beginning=True,
    )
    rounds = 0
    while mon.poll_once() > 0 and rounds < 50:
        rounds += 1
    print(f"  {mon.summary()}")

    # ------------------------------------------------------------------
    hr("第 2 步：分析 IIS 访问日志（W3C 格式）")
    mon2 = IisLogMonitor(
        alert_fn=alerter.emit,
        log_fn=alerter.log,
        analyzer=analyzer,
        sources=[{"name": "demo-iis", "path": os.path.dirname(paths["iis_log"])}],
        from_beginning=True,
    )
    rounds = 0
    while mon2.poll_once() > 0 and rounds < 50:
        rounds += 1
    print(f"  {mon2.summary()}")

    # ------------------------------------------------------------------
    hr("第 3 步：分析 auth.log（SSH 爆破、提权、建号）")
    auth = AuthMonitor(
        alert_fn=alerter.emit,
        log_fn=alerter.log,
        analyzer_rules=analyzer.rules,
        sources=[{"name": "demo-auth", "path": paths["auth_log"]}],
        from_beginning=True,
        fail_threshold=5,
        trusted_ips=["127.0.0.1"],
    )
    rounds = 0
    while auth.poll_once() > 0 and rounds < 50:
        rounds += 1
    print(f"  {auth.summary()}")

    # ------------------------------------------------------------------
    hr("第 4 步：分析 Windows 事件日志样本")
    evt = EventLogMonitor(
        alert_fn=alerter.emit,
        log_fn=alerter.log,
        rules=analyzer.rules,
        log_name="Security",
        state_dir=paths["state"],
        fail_threshold=2,
    )
    for raw in WIN_EVENTS:
        ev = EventLogMonitor._to_event(raw)
        if ev:
            evt.events_total += 1
            evt._handle(ev)
    print(f"  处理了 {evt.events_total} 个事件（演示用样本，非本机真实日志）")

    # ------------------------------------------------------------------
    hr("第 5 步：巡检 IIS 站点目录（找 ASPX 马、上传目录里的马、被改的 web.config）")
    scanner = FileScanner(
        alert_fn=alerter.emit,
        log_fn=alerter.log,
        rules=analyzer.rules,
        webroots=[paths["www_win"]],
        script_extensions=[".aspx", ".ashx", ".asp", ".php"],
        state_dir=paths["state"],
    )
    r1 = scanner.scan()
    print(f"  {r1.summary()}")

    hr("第 6 步：巡检 Linux 站点目录（找 PHP 一句话马 / 冰蝎马）")
    scanner2 = FileScanner(
        alert_fn=alerter.emit,
        log_fn=alerter.log,
        rules=analyzer.rules,
        webroots=[paths["www_lin"]],
        script_extensions=[".php"],
        state_dir=os.path.join(paths["state"], "lin"),
    )
    r2 = scanner2.scan()
    print(f"  {r2.summary()}")

    # ------------------------------------------------------------------
    hr("第 7 步：扫描「工具落地目录」（模拟攻击者往 Temp 放 exe）")
    drop = WindowsDropScanner(
        alert_fn=alerter.emit,
        log_fn=alerter.log,
        rules=analyzer.rules,
        directories=[paths["drop"]],
        lookback_days=1,
        state_dir=paths["state"],
    )
    drop.scan_once()          # 第一次只建基线
    print("  第一次扫描：只记录基线（不告警）")
    new_exe = os.path.join(paths["drop"], "beacon_x64.exe")
    with open(new_exe, "wb") as fh:
        fh.write(b"MZ" + os.urandom(4096))
    os.utime(new_exe, None)
    time.sleep(1.0)
    drop.scan_once()
    print("  第二次扫描：新增 exe 应被告警")

    # ==================================================================
    hr("检测结果")
    alerts = list(alerter.alerts)
    if not alerts:
        print("  未产生任何告警 —— 这说明规则链路有问题，请把本输出反馈给维护者。")
        return 1

    print(f"  共 {len(alerts)} 条告警\n")
    print(f"  {'级别':<9} {'判定类型':<14} {'分值':>4}  {'规则':<22} 告警内容")
    print("  " + "-" * 116)
    for a in sorted(alerts, key=lambda x: -x.score):
        title = a.title if len(a.title) <= 52 else a.title[:51] + "…"
        print(f"  {a.severity:<9} {a.tool:<14} {a.score:>4}  {a.rule_id[:22]:<22} {title}")

    # 按类型汇总
    print()
    by_tool: dict = {}
    for a in alerts:
        by_tool[a.tool] = by_tool.get(a.tool, 0) + 1
    print("  按类型：" + "、".join(f"{k} {v}" for k, v in sorted(by_tool.items(), key=lambda x: -x[1])))
    counts: dict = {}
    for a in alerts:
        counts[a.severity] = counts.get(a.severity, 0) + 1
    print("  按级别：" + "、".join(f"{Severity.cn(k)} {v}" for k, v in counts.items()))

    # 展示一条最典型的告警详情
    top = max(alerts, key=lambda x: x.score)
    hr("最典型的一条告警（完整证据）")
    print(f"  时间    : {top.time_str}")
    print(f"  级别    : {top.severity}（{Severity.cn(top.severity)}） 分值 {top.score}")
    print(f"  类型    : {top.tool}")
    print(f"  规则    : {top.rule_id}")
    print(f"  来源    : {top.source}  |  {top.flow}")
    print(f"  标题    : {top.title}")
    print(f"  证据    : {top.evidence[:400]}")
    print(f"  建议    : {top.advice[:300]}")

    hr("产物位置")
    for name, path in alerter.paths.items():
        print(f"  {name:<10} {path}")
    print(f"  仿真环境   {WORK}")
    print("\n  提示：删掉 demo-output 目录即可清理本演示产生的所有文件。")
    print("  下一步：把真正的 Web 根目录与日志路径填进 linux.json / windows.json，")
    print("         然后执行  wsp check  →  wsp start --foreground  试运行。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
