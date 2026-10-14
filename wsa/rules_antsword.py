"""
蚁剑（AntSword）流量特征规则。

来源与依据（公开研究归纳，非猜测）：
  * 默认 POST 参数：PHP 为 z0(z1/z2)，ASP/ASPX 为 z0/z1，JSP 为 z1
  * 固定初始化载荷 Base64 段：QGluaV9zZXQ… 解码为
        @ini_set("display_errors","0");@set_time_limit(0);…
    响应中回显 "X@Y"（Base64 里表现为 WEB 之类可见片段）用于分割输出
  * 默认 User-Agent 为 antSword/vX.X
  * 响应体结构：随机字符 + Base64 结果 + 随机字符
  * ASPX/ASP 采用 hex(0x…) 拼接的 .NET 代码执行
  * 各编码器特征：base64 / chr / chr16 / hex / aspx / rot13
"""

from __future__ import annotations

from .rules import Rule, KIND_ENTROPY, KIND_HEADER, KIND_META, KIND_PARAM, KIND_REGEX, KIND_SUBSTR

TOOL = "蚁剑"

#: 蚁剑初始化载荷 Base64 的固定前缀（多家厂商设备的通用检测特征）
ANTSWORD_INIT_B64 = "QGluaV9zZXQ"
ANTSWORD_INIT_B64_LONG = (
    "QGluaV9zZXQoImRpc3BsYXlfZXJyb3JzIiwiMCIpO0BzZXRfdGltZV9saW1pdCgwKTtpZihQSFBfVkVSU0lPTjwnNS4zLjAnKXtAc2V0X21hZ2ljX3F1b3Rlc19ydW50aW1lKDApO307ZWNobygiWEBZIik7"
)
#: 解码后的明文开头
ANTSWORD_INIT_PLAIN = '@ini_set("display_errors","0")'

#: 默认参数名
ANTSWORD_PARAMS = ("z0", "z1", "z2", "z3")

#: 默认 User-Agent
ANTSWORD_UA = "antSword"


def rules() -> list[Rule]:
    out: list[Rule] = []

    # --- 强特征：初始化载荷固定 Base64 段 ---------------------------------
    out.append(
        Rule(
            id="ANT-001",
            tool=TOOL,
            title="请求体中包含蚁剑固定初始化载荷（QGluaV9zZXQ…）",
            score=60,
            kind=KIND_SUBSTR,
            pattern=ANTSWORD_INIT_B64,
            fields=("body", "url", "params"),
            advice=(
                "该 Base64 段解码后为 @ini_set(\"display_errors\",\"0\");@set_time_limit(0);，"
                "是蚁剑默认连接初始化 payload 的固定前缀。请定位对应 URL 与服务器文件，"
                "确认是否为遗留 webshell 并下线，同时排查同源 IP 的其它访问记录。"
            ),
            tags=("webshell", "antsword", "强特征"),
        )
    )
    out.append(
        Rule(
            id="ANT-002",
            tool=TOOL,
            title="完整蚁剑初始化载荷片段命中（更长的固定 Base64）",
            score=25,
            kind=KIND_SUBSTR,
            pattern=ANTSWORD_INIT_B64_LONG,
            fields=("body", "params"),
            advice="命中更长的固定片段，可基本排除巧合的 Base64 碰撞。",
            tags=("webshell", "antsword", "强特征"),
        )
    )

    # --- 强特征：参数名组合 ----------------------------------------------
    out.append(
        Rule(
            id="ANT-010",
            tool=TOOL,
            title="请求参数包含蚁剑默认参数名 z0/z1/z2",
            score=35,
            kind=KIND_PARAM,
            # 至少命中 2 个默认参数名，或命中 z0 且值为 Base64/HEX 载荷
            meta={"any_of": list(ANTSWORD_PARAMS), "min_hits": 2},
            advice="蚁剑默认使用 z0/z1/z2 作为功能、参数、数据三段参数名。请核对业务接口是否真的使用这些参数名。",
            tags=("webshell", "antsword"),
        )
    )
    out.append(
        Rule(
            id="ANT-011",
            tool=TOOL,
            title="存在 z0 参数且其值为类 Base64 超长载荷",
            score=30,
            kind=KIND_PARAM,
            meta={"name": "z0", "value_regex": r"^[A-Za-z0-9+/=%]{40,}$"},
            advice="z0 为蚁剑数据通道默认参数名，取值超长且为 Base64/URL 编码，符合 webshell 载荷投递特征。",
            tags=("webshell", "antsword"),
        )
    )

    # --- 强特征：User-Agent ----------------------------------------------
    out.append(
        Rule(
            id="ANT-020",
            tool=TOOL,
            title="User-Agent 暴露蚁剑客户端（antSword/…）",
            score=70,
            kind=KIND_HEADER,
            meta={"header": "user-agent", "contains": ANTSWORD_UA},
            advice="蚁剑未修改默认 UA，可直接判定为蚁剑管理端流量。请立即定位并处置被控服务器。",
            tags=("webshell", "antsword", "客户端指纹"),
        )
    )

    # --- 编码器特征 ------------------------------------------------------
    out.append(
        Rule(
            id="ANT-030",
            tool=TOOL,
            title="载荷为 PHP chr() 十进制拼接（蚁剑 chr 编码器）",
            score=30,
            kind=KIND_REGEX,
            pattern=r"(?:chr\(\d{1,3}\)\s*\.\s*){6,}|(?:%63%68%72|\bchr\b)\s*\(\s*\d{1,3}\s*\)",
            fields=("body", "params", "url"),
            flags="i",
            advice="连续的 chr() 拼接是蚁剑 chr/chr16 编码器的典型形态，用于绕过关键字检测。",
            tags=("webshell", "antsword", "编码器"),
        )
    )
    out.append(
        Rule(
            id="ANT-031",
            tool=TOOL,
            title="载荷为 PHP hex 编码（\\x.. 连续转义）",
            score=25,
            kind=KIND_REGEX,
            pattern=r"(?:\\x[0-9a-fA-F]{2}){10,}",
            fields=("body", "params"),
            advice="蚁剑 hex 编码器输出连续 \\xNN 转义，常见于规避 WAF 的 webshell 载荷。",
            tags=("webshell", "antsword", "编码器"),
        )
    )
    out.append(
        Rule(
            id="ANT-032",
            tool=TOOL,
            title="ASP 变体：0x 十六进制 + Execute/ExecuteGlobal 代码执行",
            score=45,
            kind=KIND_REGEX,
            pattern=r"(?:Execute|ExecuteGlobal|Eval)\s*\(?\s*(?:0x[0-9a-fA-F]{8,}|Chr\()",
            fields=("body", "params"),
            flags="i",
            advice="ASP 版蚁剑会把 VBScript 代码转成 0x… 十六进制串后交付 Execute，是明确的 webshell 执行链。",
            tags=("webshell", "antsword", "asp"),
        )
    )

    # --- 通用：服务端代码执行关键字 --------------------------------------
    out.append(
        Rule(
            id="ANT-040",
            tool=TOOL,
            title="请求载荷包含 PHP 代码执行特征（eval/assert/base64_decode）",
            score=40,
            kind=KIND_REGEX,
            pattern=(
                r"(?:eval|assert|create_function|preg_replace\s*\(\s*['\"]/.*?/e|call_user_func|"
                r"base64_decode|gzinflate|str_rot13|system|shell_exec|passthru|popen|proc_open)"
                r"\s*\(|@?ini_set\s*\(\s*[\"']display_errors"
            ),
            fields=("body", "params", "url"),
            flags="i",
            advice="请求参数中直接出现 PHP 动态执行函数（多为 Base64/URL 编码包裹），属一句话木马调用行为。",
            tags=("webshell", "php", "通用"),
        )
    )
    out.append(
        Rule(
            id="ANT-041",
            tool=TOOL,
            title="请求载荷包含 .NET 动态编译/反射执行特征",
            score=40,
            kind=KIND_REGEX,
            pattern=(
                r"(?:Assembly\.Load|CSharpCodeProvider|CompileAssemblyFromSource|"
                r"System\.Reflection|Activator\.CreateInstance|Type\.GetType|"
                r"JScript\.Encode|eval\s*\(|CreateInstance)\s*\("
            ),
            fields=("body", "params"),
            flags="i",
            advice="ASPX 版蚁剑通过 .NET 动态编译或反射执行代码，正常业务极少在 POST 体中出现这些 API。",
            tags=("webshell", "aspx", "通用"),
        )
    )

    # --- 响应侧 ----------------------------------------------------------
    out.append(
        Rule(
            id="ANT-050",
            tool=TOOL,
            title="响应体为“随机字符 + Base64 + 随机字符”结构且含 X@Y 分割标记",
            score=35,
            kind=KIND_REGEX,
            pattern=r"[A-Za-z0-9+/]{8,}={0,2}.*(?:X@Y|WEB)",
            fields=("response",),
            advice="蚁剑服务端以 echo(\"X@Y\") 作为命令输出与错误信息的分隔标记，响应中出现该标记说明马已被调用。",
            tags=("webshell", "antsword", "响应特征"),
        )
    )

    # --- 行为侧（元规则）------------------------------------------------
    out.append(
        Rule(
            id="ANT-060",
            tool=TOOL,
            title="单参数名固定、请求体为大段随机字符（Base64 密文）的高频 POST",
            score=20,
            kind=KIND_ENTROPY,
            fields=("request",),
            meta={
                "min_body": 64,
                "min_entropy": 5.2,
                "single_param": True,
                "require": "antsword_param",
            },
            advice="与 z0/z1 参数名组合出现时应视为蚁剑/菜刀类工具的越权通信，请结合服务器日志确认。",
            tags=("webshell", "antsword", "行为特征"),
        )
    )

    # --- 元规则：多信号聚合 ----------------------------------------------
    out.append(
        Rule(
            id="ANT-090",
            tool=TOOL,
            title="多信号聚合判定为蚁剑会话（参数名 + 载荷 + 行为）",
            score=45,
            kind=KIND_META,
            meta={
                "require_rules": ["ANT-010"],
                "require_any": ["ANT-040", "ANT-041", "ANT-001", "ANT-011", "ANT-030"],
            },
            advice="多个独立信号同时命中，误报概率极低，建议直接按入侵事件处置。",
            tags=("webshell", "antsword", "聚合"),
        )
    )
    return out
