"""
规则模型与规则集装载。

规则类型（kind）：
    substr   子串匹配（大小写不敏感）
    regex    正则匹配
    header   单个请求头条件（等于/包含/正则/不存在）
    param    请求参数条件（默认参数名命中、取值正则、熵值）
    entropy  熵值与形态条件（请求/响应体、字节长度、分组对齐）
    meta     组合条件（引用其它规则命中结果、多头部同时成立、头部顺序）
    tls      TLS ClientHello 指纹条件

规则可来自：
    * 内置规则（wsa/rules_antsword.py 等）
    * rules/*.yaml 或 rules/*.json 用户规则（可覆盖同 id 的内置规则）
"""

from __future__ import annotations

import os
from dataclasses import replace
from typing import Any, Dict, Iterable, List, Optional

from .models import Rule
from .utils import as_list, load_structured

# ---------------------------------------------------------------------------
# 规则类型常量
# ---------------------------------------------------------------------------
KIND_SUBSTR = "substr"
KIND_REGEX = "regex"
KIND_HEADER = "header"
KIND_PARAM = "param"
KIND_ENTROPY = "entropy"
KIND_META = "meta"
KIND_TLS = "tls"
# 防守端专用规则类型（由 logs.py / filescan.py 求值）
KIND_LOG = "log"
KIND_STAT = "stat"
KIND_FILESCAN = "filescan"
KIND_FILEMETA = "filemeta"
KIND_POLICY = "policy"

#: 由 wsa.analysis 引擎直接求值的类型
ENGINE_KINDS = (KIND_SUBSTR, KIND_REGEX, KIND_HEADER, KIND_PARAM, KIND_ENTROPY, KIND_META, KIND_TLS)
#: 由各监控器自行求值的类型
MONITOR_KINDS = (KIND_LOG, KIND_STAT, KIND_FILESCAN, KIND_FILEMETA, KIND_POLICY)

VALID_KINDS = ENGINE_KINDS + MONITOR_KINDS

# ---------------------------------------------------------------------------
# 可匹配字段
# ---------------------------------------------------------------------------
FIELD_NAMES = (
    "all",        # 原始报文（请求头 + 请求体 + 响应头 + 响应体）
    "head",       # 请求头原始字节
    "body",       # 请求体
    "params",     # 解析后的参数，key=value&key2=value2 形态
    "url",        # 请求方法与完整 URL
    "request",    # 请求头 + 请求体
    "response",   # 响应头 + 响应体
    "binary",     # 双向载荷（含 TLS 明文段），用于魔数匹配
)


def builtin_rules() -> List[Rule]:
    """
    汇总所有内置规则。

    进攻工具特征规则（蚁剑/冰蝎/哥斯拉/通用 + TLS）用于识别「请求长得像什么」；
    防守端规则（rules_defense）用于识别「服务器日志与文件里出现了什么异常」。
    两类规则共用同一套打分与告警管线。
    """
    from . import rules_antsword, rules_behinder, rules_defense, rules_generic, rules_godzilla

    rules: List[Rule] = []
    for mod in (rules_antsword, rules_behinder, rules_godzilla, rules_generic, rules_defense):
        rules.extend(mod.rules())
    return rules


def _rule_from_dict(raw: Dict[str, Any], origin: str = "") -> Optional[Rule]:
    try:
        rid = str(raw["id"])
        tool = str(raw.get("tool", "自定义"))
        title = str(raw.get("title", rid))
        score = int(raw.get("score", 20))
    except (KeyError, TypeError, ValueError):
        return None
    kind = str(raw.get("kind", KIND_SUBSTR))
    if kind not in VALID_KINDS:
        kind = KIND_SUBSTR
    return Rule(
        id=rid,
        tool=tool,
        title=title,
        score=score,
        severity=str(raw.get("severity", "")),
        kind=kind,
        pattern=str(raw.get("pattern", "")),
        fields=tuple(as_list(raw.get("fields", ["all"]))) or ("all",),
        flags=str(raw.get("flags", "")),
        advice=str(raw.get("advice", "")),
        enabled=bool(raw.get("enabled", True)),
        tags=tuple(as_list(raw.get("tags", ()))),
        min_len=int(raw.get("min_len", 0)),
        max_entropy=float(raw.get("max_entropy", 0.0)),
        meta=dict(raw.get("meta", {}) or {}),
    )


def load_rule_files(rule_dir: str) -> tuple[List[Rule], List[str]]:
    """
    从目录载入 *.yaml/*.yml/*.json 用户规则。
    返回 (规则列表, 提示信息列表)。文件格式：
        rules:
          - id: MY-001
            tool: 蚁剑
            title: ...
            score: 30
            kind: substr
            pattern: "z0="
            fields: [body]
    """
    rules: List[Rule] = []
    notes: List[str] = []
    if not rule_dir or not os.path.isdir(rule_dir):
        return rules, notes
    for name in sorted(os.listdir(rule_dir)):
        if not name.lower().endswith((".yaml", ".yml", ".json")):
            continue
        path = os.path.join(rule_dir, name)
        try:
            data = load_structured(path)
        except Exception as exc:  # 配置写错不应该让程序崩溃
            notes.append(f"规则文件 {name} 解析失败：{exc}")
            continue
        if data is None:
            if name.lower().endswith((".yaml", ".yml")):
                notes.append(f"规则文件 {name} 未解析（可能未安装 PyYAML，可改用同名 .json）")
            continue
        items = data.get("rules", []) if isinstance(data, dict) else data
        count = 0
        for raw in as_list(items):
            if not isinstance(raw, dict):
                continue
            rule = _rule_from_dict(raw, origin=name)
            if rule:
                rules.append(rule)
                count += 1
        notes.append(f"规则文件 {name} 载入 {count} 条规则")
    return rules, notes


def merge_rules(builtin: Iterable[Rule], user: Iterable[Rule]) -> List[Rule]:
    """用户规则按 id 覆盖内置规则，其余追加。"""
    merged: Dict[str, Rule] = {r.id: r for r in builtin}
    for r in user:
        merged[r.id] = r
    return list(merged.values())


def build_rule_set(rule_dir: str = "") -> tuple[List[Rule], List[str]]:
    user, notes = load_rule_files(rule_dir)
    return merge_rules(builtin_rules(), user), notes


def disable_rules(rules: List[Rule], ids: Iterable[str]) -> List[Rule]:
    banned = {i.strip() for i in ids if str(i).strip()}
    if not banned:
        return rules
    return [replace(r, enabled=False) if r.id in banned else r for r in rules]
