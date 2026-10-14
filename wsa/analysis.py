"""
检测引擎：把规则库应用到 HTTP 事务 / TCP 流 / TLS 指纹上，产出告警。

打分与判定原则（刻意设计为“可解释、可调参、可解释误报”）：
  1. 每条规则独立给出分值，同一条规则在一个事务内只计一次（取最高证据）；
  2. 同一工具的分值在同一流内累加，跨工具不互相掩护；
  3. 严重级别由累计分值映射：>=110 严重 / >=70 高危 / >=40 中危 / >=15 低危；
  4. 强特征（默认密钥、固定载荷段、固定响应结构）单独就能达到中危以上，
     弱特征（Host 位置、Cookie 尾分号）单独不足以告警，避免噪声；
  5. 所有判定都附带证明过程（evidence），便于人工复核是否为误报。
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from . import http as httpmod
from . import tls as tlsmod
from .evidence import (
    CryptoProbe,
    DecryptionResult,
    entropy_of,
)
from .models import (
    Alert,
    Flow,
    Rule,
    Severity,
    HttpTransaction,
)
from .rules import (
    ENGINE_KINDS,
    KIND_ENTROPY,
    KIND_HEADER,
    KIND_META,
    KIND_PARAM,
    KIND_REGEX,
    KIND_SUBSTR,
    KIND_TLS,
    build_rule_set,
)
from .utils import looks_base64, printable_ratio, shannon_entropy, to_text

#: 低于该分值不产生告警（仍计入统计）
DEFAULT_MIN_SCORE = 15


@dataclass
class Finding:
    """一条规则命中记录。"""

    rule: Rule
    score: int
    evidence: str
    detail: str = ""


@dataclass
class AnalysisOptions:
    min_score: int = DEFAULT_MIN_SCORE
    try_decrypt: bool = True
    passwords: Sequence[str] = ()
    max_body_scan: int = 65536
    #: 只对命中工具特征的流做解密（省时间）
    decrypt_only_suspicious: bool = True


# ---------------------------------------------------------------------------
# 事务上下文：把一条 HTTP 事务摊平成可匹配的字段
# ---------------------------------------------------------------------------
@dataclass
class TransactionContext:
    txn: HttpTransaction
    flow: Flow
    fields: Dict[str, str] = field(default_factory=dict)
    raw_params: Dict[str, str] = field(default_factory=dict)
    params: Dict[str, str] = field(default_factory=dict)
    header_list: List[Tuple[str, str]] = field(default_factory=list)
    body_text: str = ""
    resp_text: str = ""
    hits: Dict[str, bool] = field(default_factory=dict)
    decryptions: Dict[str, DecryptionResult] = field(default_factory=dict)


def _decode(data: bytes, limit: int) -> str:
    if not data:
        return ""
    return data[:limit].decode("latin-1", "ignore")


def build_context(
    txn: HttpTransaction, flow: Flow, probe: Optional[CryptoProbe], opts: AnalysisOptions
) -> TransactionContext:
    """构造匹配上下文（含可选解密取证）。"""
    limit = opts.max_body_scan
    host = txn.host or flow.key.dst_ip
    url = f"{txn.method} http://{host}{txn.path}" if txn.method else ""
    # 原始参数（保留编码形态）+ 解码参数
    raw_params: Dict[str, str] = {}
    if txn.body and txn.method in ("POST", "PUT", "PATCH"):
        ctype = (txn.headers.get("content-type") or "").lower()
        if "application/x-www-form-urlencoded" in ctype or (
            not ctype and b"=" in txn.body[:512]
        ):
            for pair in txn.body[:limit].split(b"&"):
                if b"=" not in pair:
                    continue
                k, _, v = pair.partition(b"=")
                raw_params[k.decode("latin-1", "ignore")] = v.decode("latin-1", "ignore")
    params = httpmod.parse_params(txn.method, txn.path, txn.headers, txn.body[:limit])
    for k, v in raw_params.items():
        params.setdefault(k, v)

    param_blob = "&".join(f"{k}={v}" for k, v in list(params.items())[:40])
    head = _decode(txn.raw_head, 8192)
    body = _decode(txn.body, limit)
    resp_head = _decode(txn.resp_head, 8192)
    resp_body = _decode(txn.resp_body, limit)
    binary = (txn.body[:limit] + b"\x00" + txn.resp_body[:limit]).decode("latin-1", "ignore")
    # 说明：response 字段只放响应体（没有响应体时才退化为响应头），
    # 这样 ^...$ 这类整体结构正则可以精确匹配响应内容，
    # 不会被拼在开头的响应头破坏锚点。需要看响应头时请用 all 字段。
    response_field = resp_body if resp_body else resp_head

    fields = {
        "all": "\r\n".join([head, body, resp_head, resp_body]),
        "head": head,
        "body": body,
        "params": param_blob,
        "url": url,
        "request": head + "\r\n" + body,
        "response": response_field,
        "response_head": resp_head,
        "binary": binary,
    }
    ctx = TransactionContext(
        txn=txn,
        flow=flow,
        fields=fields,
        raw_params=raw_params,
        params=params,
        header_list=txn.raw_headers,
        body_text=body,
        resp_text=resp_body,
    )
    if probe is not None:
        try:
            results = probe.probe_request(raw_params, txn.body[:limit], txn.headers.get("content-type", ""))
        except Exception:
            results = []
        ctx.decryptions = {f"decrypt-{r.scheme}-{r.key}": r for r in results}
    return ctx


# ---------------------------------------------------------------------------
# 单个规则的求值
# ---------------------------------------------------------------------------
def _field_texts(ctx: TransactionContext, rule: Rule) -> List[Tuple[str, str]]:
    names = rule.fields or ("all",)
    out = []
    for n in names:
        if n in ctx.fields:
            out.append((n, ctx.fields[n]))
    return out or [("all", ctx.fields.get("all", ""))]


def _first_evidence(text: str, needle: str, width: int = 80) -> str:
    idx = text.lower().find(needle.lower())
    if idx < 0:
        return ""
    start = max(0, idx - width // 2)
    frag = text[start : start + width]
    frag = "".join(ch if ch.isprintable() or ch in "\r\n\t" else "." for ch in frag)
    return frag.replace("\r\n", " ").replace("\n", " ")


def eval_substr(ctx: TransactionContext, rule: Rule) -> Optional[Finding]:
    if not rule.pattern:
        return None
    needle = rule.pattern
    for name, text in _field_texts(ctx, rule):
        if not text:
            continue
        if needle.lower() in text.lower():
            ev = _first_evidence(text, needle)
            return Finding(rule, rule.score, f"字段[{name}]命中 {needle[:40]} … 片段: {ev}")
    return None


def eval_regex(ctx: TransactionContext, rule: Rule) -> Optional[Finding]:
    if not rule.pattern:
        return None
    flags = 0
    if "i" in rule.flags.lower():
        flags |= re.IGNORECASE
    if "m" in rule.flags.lower():
        flags |= re.MULTILINE
    if "s" in rule.flags.lower():
        flags |= re.DOTALL
    try:
        pattern = re.compile(rule.pattern, flags)
    except re.error:
        return None
    for name, text in _field_texts(ctx, rule):
        if not text:
            continue
        m = pattern.search(text)
        if m:
            frag = m.group(0)[:120]
            frag = "".join(ch if ch.isprintable() else "." for ch in frag)
            return Finding(rule, rule.score, f"字段[{name}]正则命中: {frag}")
    return None


def _header_get(headers: Dict[str, str], name: str) -> str:
    return headers.get(name.lower(), "")


def eval_header(ctx: TransactionContext, rule: Rule) -> Optional[Finding]:
    meta = rule.meta or {}
    name = str(meta.get("header", "")).lower()
    if not name:
        return None
    value = _header_get(ctx.txn.headers, name)
    if not value:
        if meta.get("missing"):
            return Finding(rule, rule.score, f"请求头 {name} 缺失（按规则要求）")
        return None
    if "contains" in meta and str(meta["contains"]).lower() not in value.lower():
        return None
    if "equals_any" in meta:
        pool = [str(p) for p in meta["equals_any"]]
        if value.strip() not in pool:
            return None
    if "regex" in meta:
        try:
            if not re.search(str(meta["regex"]), value, re.IGNORECASE):
                return None
        except re.error:
            return None
    detail = f"请求头 {name}: {value[:150]}"
    return Finding(rule, rule.score, detail)


def eval_param(ctx: TransactionContext, rule: Rule) -> Optional[Finding]:
    meta = rule.meta or {}
    params = ctx.params
    if not params:
        return None
    lower_map = {k.lower(): (k, v) for k, v in params.items()}

    # 形态一：默认参数名命中数量
    if "any_of" in meta:
        names = [str(n).lower() for n in meta["any_of"]]
        hits = [lower_map[n][0] for n in names if n in lower_map]
        need = int(meta.get("min_hits", 1))
        if len(hits) < need:
            return None
        value_regex = meta.get("value_regex")
        if value_regex:
            try:
                pat = re.compile(str(value_regex))
            except re.error:
                pat = None
            if pat and not any(pat.match(lower_map[n][1]) for n in names if n in lower_map):
                return None
        return Finding(
            rule,
            rule.score,
            f"命中默认参数名 {', '.join(hits)}（共 {len(params)} 个参数）",
        )

    # 形态二：指定参数名 + 取值正则
    if "name" in meta:
        key = str(meta["name"]).lower()
        if key not in lower_map:
            return None
        real_name, value = lower_map[key]
        vre = meta.get("value_regex")
        if vre:
            try:
                if not re.match(str(vre), value):
                    return None
            except re.error:
                return None
        return Finding(rule, rule.score, f"参数 {real_name} 取值形态命中（长度 {len(value)}）")

    # 形态三：任意参数取值命中正则（可限制参数总数）
    if "value_regex" in meta:
        max_params = int(meta.get("max_params", 0))
        if max_params and len(params) > max_params:
            return None
        try:
            pat = re.compile(str(meta["value_regex"]))
        except re.error:
            return None
        ent_min = float(meta.get("entropy_min", 0.0))
        for k, v in params.items():
            if pat.match(v):
                if ent_min and entropy_of(v) < ent_min:
                    continue
                return Finding(
                    rule,
                    rule.score,
                    f"参数 {k} 为 {len(v)} 字符密文（熵 {entropy_of(v):.2f}）",
                )
        return None

    # 形态四：需要参数名与正则同时成立
    if "param_any" in meta:
        names = [str(n).lower() for n in meta["param_any"]]
        present = [n for n in names if n in lower_map]
        if not present:
            return None
        regexes = [str(p) for p in meta.get("regex_any", [])]
        haystack = ctx.fields.get("request", "") + "&" + ctx.fields.get("params", "")
        for rx in regexes:
            try:
                if re.search(rx, haystack, re.IGNORECASE):
                    return Finding(rule, rule.score, f"参数 {present[0]} 与编解码特征同时出现")
            except re.error:
                continue
        return None
    return None


def eval_entropy(ctx: TransactionContext, rule: Rule) -> Optional[Finding]:
    meta = rule.meta or {}
    target = rule.fields[0] if rule.fields else "body"
    if target == "flow":
        return None  # 流级条件在 analyze_flow 中处理

    raw = {
        "body": ctx.txn.body,
        "response": ctx.txn.resp_body,
        "request": ctx.txn.raw_head + ctx.txn.body,
        "all": ctx.txn.body + ctx.txn.resp_body,
    }.get(target, ctx.txn.body)
    if not raw:
        return None

    min_len = int(meta.get("min_len", meta.get("min_body", 0)))
    if min_len and len(raw) < min_len:
        return None
    if meta.get("require_method") and ctx.txn.method not in meta["require_method"]:
        return None
    if meta.get("require_status") and ctx.txn.status not in meta["require_status"]:
        return None
    if meta.get("require_content_type"):
        ctype = (ctx.txn.headers.get("content-type") or "").lower()
        if not any(str(c).lower() in ctype for c in meta["require_content_type"]):
            return None
    if meta.get("require_path_regex"):
        try:
            if not re.search(str(meta["require_path_regex"]), ctx.txn.path, re.IGNORECASE):
                return None
        except re.error:
            return None

    text = raw[: 65536]
    ent = shannon_entropy(text)
    if ent < float(meta.get("min_entropy", 0.0)):
        return None
    if "max_entropy" in meta and ent > float(meta["max_entropy"]):
        return None
    if meta.get("forbid_printable_ratio"):
        if printable_ratio(text) >= float(meta["forbid_printable_ratio"]):
            return None
    if meta.get("charset") == "base64":
        if not looks_base64(text.decode("latin-1", "ignore"), 24):
            return None
    if meta.get("length_multiple"):
        if len(text) % int(meta["length_multiple"]) != 0:
            return None
    if meta.get("single_param"):
        if len(ctx.params) > 1:
            return None
    if meta.get("require_param_any"):
        names = {str(n).lower() for n in meta["require_param_any"]}
        if not (names & {k.lower() for k in ctx.params}):
            return None
    if meta.get("require_param_name"):
        want = {str(n).lower() for n in meta["require_param_name"]}
        if not want.issubset({k.lower() for k in ctx.params}):
            return None
    if meta.get("require") == "antsword_param":
        if not any(n.lower() in ("z0", "z1", "z2") for n in ctx.params):
            return None
    return Finding(
        rule,
        rule.score,
        f"{target} 长度 {len(text)} 字节，Shannon 熵 {ent:.2f} bit/byte（接近均匀分布=密文）",
    )


def eval_meta(ctx: TransactionContext, rule: Rule, hits: Dict[str, bool]) -> Optional[Finding]:
    meta = rule.meta or {}
    reasons: List[str] = []

    # 1) 引用其它规则
    for rid in meta.get("require_rules", []) or []:
        if not hits.get(str(rid)):
            return None
        reasons.append(str(rid))
    if "require_any" in meta:
        found = [str(r) for r in meta["require_any"] if hits.get(str(r))]
        if not found:
            return None
        reasons.extend(found)
    if "also_any" in meta:
        found = [str(r) for r in meta["also_any"] if hits.get(str(r))]
        if not found:
            return None
        reasons.extend(found)

    # 2) 多个请求头同时成立 / 某些请求头必须缺失
    for cond in meta.get("header_all", []) or []:
        name = str(cond.get("header", "")).lower()
        value = _header_get(ctx.txn.headers, name)
        ok = False
        if cond.get("contains"):
            ok = str(cond["contains"]).lower() in value.lower()
        elif cond.get("equals"):
            ok = value.strip() == str(cond["equals"])
        elif cond.get("regex"):
            try:
                ok = bool(re.search(str(cond["regex"]), value, re.IGNORECASE))
            except re.error:
                ok = False
        if not ok:
            return None
        reasons.append(f"{name}={'✓'}")
    for cond in meta.get("require_not", []) or []:
        name = str(cond.get("header", "")).lower()
        if _header_get(ctx.txn.headers, name):
            return None
        reasons.append(f"缺少 {name}")

    # 3) 请求头数量与 Host 位置
    if meta.get("min_headers"):
        total = len(ctx.header_list)
        if total < int(meta["min_headers"]):
            return None
        reasons.append(f"头部数 {total}")
    if meta.get("host_order_after") is not None:
        idx = -1
        for i, (name, _v) in enumerate(ctx.header_list):
            if name.lower() == "host":
                idx = i
                break
        if idx < 0 or idx <= int(meta["host_order_after"]):
            return None
        reasons.append(f"Host 位于第 {idx + 1} 个头部（正常应在前 2 位）")

    # 4) 参数名 + 正则组合
    if meta.get("param_any"):
        names = [str(n).lower() for n in meta["param_any"]]
        present = [n for n in names if n in {k.lower() for k in ctx.params}]
        if not present:
            return None
        regexes = [str(p) for p in meta.get("regex_any", [])]
        blob = ctx.fields.get("request", "")
        if not any(_safe_search(rx, blob) for rx in regexes):
            return None
        reasons.append(f"参数 {present[0]} + 编解码特征")

    # 5) 体为 Base64 且足够长
    if meta.get("require_body_base64"):
        text = ctx.body_text
        if not looks_base64(text, int(meta.get("min_body", 32))):
            return None
        reasons.append(f"请求体为 {len(text)} 字符 Base64")

    if not reasons:
        return None
    return Finding(rule, rule.score, "组合条件成立：" + ", ".join(reasons))


def _safe_search(pattern: str, text: str) -> bool:
    try:
        return bool(re.search(pattern, text, re.IGNORECASE))
    except re.error:
        return False


def eval_tls(flow: Flow, rule: Rule, ua: str) -> Optional[Finding]:
    meta = rule.meta or {}
    if not flow.tls:
        return None
    info = flow.tls[0]
    kind = tlsmod.client_kind(info)
    reasons: List[str] = []

    if "client_kind" in meta and kind != meta["client_kind"]:
        return None
    if meta.get("known_non_browser"):
        name = tlsmod.KNOWN_JA3.get(info.ja3_hash, "")
        if not name:
            return None
        if not meta.get("any_known") and tlsmod.client_kind(info) == "browser":
            return None
        reasons.append(f"指纹库={name}")
    if meta.get("alpn_exact") is not None:
        if list(info.alpn) != list(meta["alpn_exact"]):
            return None
        reasons.append(f"ALPN={','.join(info.alpn)}")
    if meta.get("ua_not_browser"):
        if not ua:
            return None
        low = ua.lower()
        looks_browser = any(
            k in low for k in ("mozilla", "chrome", "firefox", "safari", "edge", "msie", "trident")
        )
        if not looks_browser:
            return None
        reasons.append(f"UA 声称浏览器: {ua[:60]}")
    if "max_ciphers" in meta and info.cipher_count > int(meta["max_ciphers"]):
        return None
    if "max_extensions" in meta and info.ext_count > int(meta["max_extensions"]):
        return None
    if meta.get("no_alpn") and info.alpn:
        return None

    reasons.append(tlsmod.ja3_hint(info))
    return Finding(rule, rule.score, " | ".join(reasons))


# ---------------------------------------------------------------------------
# 流级规则（请求频率、等长心跳）
# ---------------------------------------------------------------------------
def eval_flow_rule(flow: Flow, rule: Rule) -> Optional[Finding]:
    meta = rule.meta or {}
    txns = flow.transactions
    if not txns:
        return None
    min_requests = int(meta.get("min_requests", 0))
    if min_requests and len(txns) < min_requests:
        return None
    window = float(meta.get("window_sec", 0))
    if window and len(txns) > 1:
        span = txns[-1].ts - txns[0].ts
        if span > window:
            return None
    if meta.get("uniform_body_len"):
        lengths = [len(t.body) for t in txns if t.body]
        if len(lengths) < min_requests:
            return None
        if len(set(lengths)) > max(2, len(lengths) // 3):
            return None
        return Finding(
            rule,
            rule.score,
            f"{len(txns)} 次请求中请求体长度高度一致（{sorted(set(lengths))[:4]}），呈心跳式通信",
        )
    return Finding(rule, rule.score, f"{len(txns)} 次请求集中在 {window:.0f}s 内")


# ---------------------------------------------------------------------------
# 分析器
# ---------------------------------------------------------------------------
def _summarize_title(items: List["Finding"]) -> str:
    """
    生成告警标题。

    单条命中直接用规则标题；多条命中时把前两条最关键的标题串起来，
    只在第三条及以后用「另有 N 项」概括 —— 这样标题能体现到底命中了什么，
    而不是永远只显示分值最高的那一条（早期版本会把蚁剑流量显示成冰蝎规则）。
    """
    if not items:
        return ""
    if len(items) == 1:
        return items[0].rule.title
    head = " ＋ ".join(i.rule.title for i in items[:2])
    if len(items) > 2:
        head += f"（另有 {len(items) - 2} 项关联特征）"
    return head


class Analyzer:
    """把规则库应用到流上，产出告警。"""

    def __init__(
        self,
        rule_dir: str = "rules",
        options: Optional[AnalysisOptions] = None,
        disabled_rules: Iterable[str] = (),
        enabled_tools: Optional[Iterable[str]] = None,
    ):
        from .rules import disable_rules

        rules, notes = build_rule_set(rule_dir)
        self.rules = [r for r in disable_rules(rules, disabled_rules) if r.enabled]
        self.rule_notes = notes
        self.options = options or AnalysisOptions()
        self.enabled_tools = set(enabled_tools) if enabled_tools else None
        self.probe = (
            CryptoProbe(passwords=self.options.passwords) if self.options.try_decrypt else None
        )
        self.stats = {
            "transactions": 0,
            "flows": 0,
            "alerts": 0,
            "rules": len(self.rules),
            "decryptions": 0,
            "started": time.time(),
        }

    # -- 对外接口 ---------------------------------------------------------
    def analyze_flow(self, flow: Flow) -> List[Alert]:
        """分析一条流，返回告警列表（同时把分值写回 flow）。"""
        self.stats["flows"] += 1
        alerts: List[Alert] = []
        if not flow.transactions and not flow.tls:
            return alerts

        ua = ""
        for t in flow.transactions:
            if t.headers.get("user-agent"):
                ua = t.headers["user-agent"]
                break

        if not flow.transactions:
            # 纯 TLS 流（加密隧道）：只能用协议指纹判定
            findings = self._eval_tls_rules(flow, ua)
            alerts.extend(self._finalize(flow, [], findings, None))
            return alerts

        flow_findings: List[Finding] = []
        decryptions: List[DecryptionResult] = []
        for txn in flow.transactions:
            self.stats["transactions"] += 1
            ctx = build_context(txn, flow, self.probe, self.options)
            if ctx.decryptions:
                decryptions.extend(ctx.decryptions.values())
            findings = self._eval_transaction(ctx)
            for f in findings:
                txn.note = (txn.note + " " + f.rule.id).strip()
            flow_findings.extend(findings)

        # TLS 规则（若该流同时有明文与指纹，合并计分）
        flow_findings.extend(self._eval_tls_rules(flow, ua))
        # 流级规则
        for rule in self.rules:
            if rule.kind == KIND_ENTROPY and rule.fields and rule.fields[0] == "flow":
                f = eval_flow_rule(flow, rule)
                if f:
                    flow_findings.append(f)

        if decryptions:
            self.stats["decryptions"] += len(decryptions)
            flow_findings.extend(self._decryption_findings(decryptions))
        alerts.extend(self._finalize(flow, flow.transactions, flow_findings, decryptions))
        return alerts

    # -- 内部：规则求值 ---------------------------------------------------
    def _eval_transaction(self, ctx: TransactionContext) -> List[Finding]:
        hits: Dict[str, bool] = {}
        findings: List[Finding] = []
        # 第一遍：非 meta 规则（只处理本引擎负责的规则类型，
        # 防守端的 log/stat/filescan 等类型由各监控器自行求值）
        for rule in self.rules:
            if rule.kind not in ENGINE_KINDS or not self._tool_enabled(rule):
                continue
            f: Optional[Finding] = None
            try:
                if rule.kind == KIND_SUBSTR:
                    f = eval_substr(ctx, rule)
                elif rule.kind == KIND_REGEX:
                    f = eval_regex(ctx, rule)
                elif rule.kind == KIND_HEADER:
                    f = eval_header(ctx, rule)
                elif rule.kind == KIND_PARAM:
                    f = eval_param(ctx, rule)
                elif rule.kind == KIND_ENTROPY:
                    if not (rule.fields and rule.fields[0] == "flow"):
                        f = eval_entropy(ctx, rule)
            except Exception:
                f = None
            if f:
                findings.append(f)
                hits[rule.id] = True
        # 第二遍：meta 规则（依赖第一遍结果）
        for rule in self.rules:
            if rule.kind != KIND_META or not self._tool_enabled(rule):
                continue
            try:
                f = eval_meta(ctx, rule, hits)
            except Exception:
                f = None
            if f:
                findings.append(f)
                hits[rule.id] = True
        return findings

    def _eval_tls_rules(self, flow: Flow, ua: str) -> List[Finding]:
        out: List[Finding] = []
        for rule in self.rules:
            if rule.kind != KIND_TLS or not self._tool_enabled(rule):
                continue
            f = eval_tls(flow, rule, ua)
            if f:
                out.append(f)
        return out

    def _tool_enabled(self, rule: Rule) -> bool:
        return self.enabled_tools is None or rule.tool in self.enabled_tools

    def _decryption_findings(self, results: List[DecryptionResult]) -> List[Finding]:
        """解密成功本身就是强证据：直接给出高分告警。"""
        out: List[Finding] = []
        seen = set()
        for r in results:
            key = (r.scheme, r.key, r.plaintext[:64])
            if key in seen:
                continue
            seen.add(key)
            tool = "冰蝎" if "冰蝎" in r.scheme else "加密载荷"
            score = 55 + min(20, r.confidence // 3)
            rule = Rule(
                id="CRY-001",
                tool=tool,
                title=f"成功解密出明文载荷（{r.scheme}，密钥 {r.key}）",
                score=score,
                kind="virtual",
                advice=(
                    "已用已知/默认密钥还原出攻击载荷明文，请据此确认被执行的命令与落地文件，"
                    "并按入侵事件流程处置。"
                ),
                tags=("webshell", "已确认", "取证"),
            )
            out.append(Finding(rule, score, f"{r.notes} | 明文预览: {r.preview[:200]}"))
        return out

    # -- 内部：汇总为告警 ------------------------------------------------
    def _finalize(
        self,
        flow: Flow,
        txns: List[HttpTransaction],
        findings: List[Finding],
        decryptions: Optional[List[DecryptionResult]] = None,
    ) -> List[Alert]:
        if not findings:
            return []
        # 同一规则只保留分值最高的一条证据
        best: Dict[str, Finding] = {}
        for f in findings:
            cur = best.get(f.rule.id)
            if cur is None or f.score > cur.score:
                best[f.rule.id] = f
        by_tool: Dict[str, List[Finding]] = {}
        for f in best.values():
            by_tool.setdefault(f.rule.tool, []).append(f)

        alerts: List[Alert] = []
        for tool, items in by_tool.items():
            total = sum(i.score for i in items)
            # 多信号加成：命中规则越多，越不可能是巧合
            if len(items) >= 3:
                total += 15
            elif len(items) == 2:
                total += 6
            if total < self.options.min_score:
                continue
            severity = Severity.from_score(total)
            items.sort(key=lambda x: -x.score)
            top = items[0]
            title = _summarize_title(items)
            first = txns[0] if txns else None
            alert = Alert(
                ts=(first.ts if first and first.ts else flow.first_ts or time.time()),
                severity=severity,
                tool=tool,
                title=title,
                rule_id=",".join(i.rule.id for i in items),
                score=total,
                flow=str(flow.key),
                source=flow.source,
                evidence=" || ".join(f"{i.rule.id}: {i.evidence}" for i in items),
                request=self._render_request(first) if first else (flow.tls[0].ja3 if flow.tls else ""),
                response=self._render_response(first) if first else "",
                advice=top.rule.advice,
                tags=tuple(sorted({t for i in items for t in i.rule.tags})),
            )
            alerts.append(alert)
            flow.score = max(flow.score, total)
            verdicts = {i.rule.tool for i in items}
            flow.verdict = "/".join(sorted(verdicts))
        self.stats["alerts"] += len(alerts)
        return alerts

    @staticmethod
    def _render_request(txn: HttpTransaction) -> str:
        head = to_text(txn.raw_head, 900)
        body = to_text(txn.body, 700)
        return (head + ("\n\n[请求体]\n" + body if body else ""))[:1800]

    @staticmethod
    def _render_response(txn: HttpTransaction) -> str:
        head = to_text(txn.resp_head, 500)
        body = to_text(txn.resp_body, 700)
        return (head + ("\n\n[响应体]\n" + body if body else ""))[:1400]
