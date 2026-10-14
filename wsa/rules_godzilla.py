"""
哥斯拉（Godzilla）流量特征规则。

依据（公开流量研究与默认配置归纳）：
  * 请求参数默认 pass（部分版本另带 key/内容参数），值为 Base64 密文
  * 响应体结构：md5前16位 + Base64数据 + md5后16位（32 位 MD5 字符串被劈成两半）
    例如 "d0e1…" + "BASE64…" + "…8f3a"
  * Cookie 末尾多出一个分号（";" 结尾），浏览器不会产生这种形态
  * 默认 User-Agent 直接暴露 JDK/运行环境信息，例如
        Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0
        Java/1.8.0_181
        Mozilla/4.0 (compatible; MSIE 8.0; ...) 配合 Accept: text/html, image/gif, …
  * Accept 默认 text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2
  * JSP 载荷出现 xc/pass 参数、Java 反射链（ClassLoader / getClass().getClassLoader()）
  * 请求体常见两种：pass=<URL编码的Base64> 或 直接是二进制乱码
"""

from __future__ import annotations

from .rules import Rule, KIND_ENTROPY, KIND_HEADER, KIND_META, KIND_PARAM, KIND_REGEX

TOOL = "哥斯拉"

#: 哥斯拉 PHP 默认配置的 User-Agent
GODZILLA_UA_FIREFOX84 = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0"
)
#: 哥斯拉默认 Accept
GODZILLA_ACCEPT = "text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2"
#: 哥斯拉 Accept-Language
GODZILLA_ACCEPT_LANG = "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2"
#: 默认参数名
GODZILLA_PARAMS = ("pass", "key", "content", "zzz", "xc")

#: Java 反射 / 类加载关键字
JAVA_REFLECTION = (
    r"ClassLoader|defineClass|getClass\(\)|getClassLoader|java\.lang\.reflect|"
    r"ProcessBuilder|Runtime\.getRuntime|java\.io\.|javax\.crypto|PageContext|pageContext"
)


def rules() -> list[Rule]:
    out: list[Rule] = []

    # --- 高置信响应结构 --------------------------------------------------
    out.append(
        Rule(
            id="GOD-001",
            tool=TOOL,
            title="响应体为 16位十六进制 + Base64 + 16位十六进制 的哥斯拉特征结构",
            score=65,
            kind=KIND_REGEX,
            pattern=(
                r"^[\s\"']*[0-9a-fA-F]{16}[A-Za-z0-9+/=\r\n]{16,}[0-9a-fA-F]{16}[\s\"']*$"
            ),
            fields=("response",),
            advice=(
                "哥斯拉把一次通信使用的 32 位 MD5 拆成前后两半夹住 Base64 数据，形成固定的响应外形。"
                "该结构在正常业务响应中几乎不可能出现，可直接判定为哥斯拉马回包。"
            ),
            tags=("webshell", "godzilla", "强特征", "响应特征"),
        )
    )
    out.append(
        Rule(
            id="GOD-002",
            tool=TOOL,
            title="请求体为 Base64/URL 编码密文但末尾缺少标准填充（哥斯拉编码器特征）",
            score=20,
            kind=KIND_REGEX,
            pattern=r"(?:pass|key|content)=[A-Za-z0-9+/%]{24,}={0,2}(?=\s|&|$)",
            fields=("body", "url", "params"),
            advice="哥斯拉自定义 Base64 编码器会去掉末尾的 = 填充，长度不满足 4 的倍数。",
            tags=("webshell", "godzilla", "编码特征"),
        )
    )
    out.append(
        Rule(
            id="GOD-003",
            tool=TOOL,
            title="请求仅携带一个超长编码/乱码参数（单一数据通道）",
            score=20,
            kind=KIND_ENTROPY,
            fields=("body",),
            meta={
                "min_body": 48,
                "min_entropy": 5.2,
                "single_param": True,
                "require_method": ["POST"],
                "require_param_any": ["pass", "key", "content", "data", "xc", "zzz"],
            },
            advice=(
                "正常业务 POST 通常同时携带多个字段；只用一个超长参数承载数据，"
                "是 webshell 管理端单通道通信的典型形态，可结合响应结构确认。"
            ),
            tags=("webshell", "godzilla", "行为特征"),
        )
    )

    # --- 客户端指纹 ------------------------------------------------------
    out.append(
        Rule(
            id="GOD-010",
            tool=TOOL,
            title="User-Agent 为哥斯拉 PHP 默认值（Firefox 84.0）",
            score=40,
            kind=KIND_HEADER,
            meta={"header": "user-agent", "contains": GODZILLA_UA_FIREFOX84},
            advice="该 UA 是哥斯拉默认配置内置值，配合 Cookie 尾分号可确认。",
            tags=("webshell", "godzilla", "客户端指纹"),
        )
    )
    out.append(
        Rule(
            id="GOD-011",
            tool=TOOL,
            title="User-Agent 暴露 Java 运行环境（Java/1.x、okhttp、Apache-HttpClient 等）",
            score=45,
            kind=KIND_HEADER,
            meta={
                "header": "user-agent",
                "regex": r"(?:^|\s)(?:Java/1\.\d|okhttp/|Apache-HttpClient/|HttpClient/|ApacheBench/)",
            },
            advice=(
                "使用 JDK 自带 HttpURLConnection/okhttp 直接访问 Web 服务，"
                "说明请求由程序而非浏览器发出，是 webshell 管理端的典型形态。"
            ),
            tags=("webshell", "通用", "客户端指纹"),
        )
    )
    out.append(
        Rule(
            id="GOD-012",
            tool=TOOL,
            title="哥斯拉默认 Accept/Accept-Language 组合且缺少 sec-fetch-* 头部",
            score=30,
            kind=KIND_META,
            meta={
                "header_all": [
                    {"header": "accept", "contains": GODZILLA_ACCEPT},
                    {"header": "accept-language", "contains": "zh-CN,zh;q=0.8,zh-TW;q=0.7"},
                ],
                "require_not": [{"header": "sec-fetch-mode"}],
            },
            advice="默认头部组合来自哥斯拉客户端配置，缺少浏览器必然发送的 sec-fetch-* 头部进一步印证。",
            tags=("webshell", "godzilla", "头部指纹"),
        )
    )
    out.append(
        Rule(
            id="GOD-013",
            tool=TOOL,
            title="Cookie 以分号结尾（哥斯拉/冰蝎系工具生成的畸形 Cookie）",
            score=20,
            kind=KIND_HEADER,
            meta={"header": "cookie", "regex": r";\s*$"},
            advice="浏览器不会输出以分号结尾的 Cookie，属工具生成流量的辅助特征。",
            tags=("webshell", "godzilla", "弱特征"),
        )
    )

    # --- 参数与载荷 ------------------------------------------------------
    out.append(
        Rule(
            id="GOD-020",
            tool=TOOL,
            title="POST 参数 pass/key 携带超长 Base64 或二进制密文",
            score=30,
            kind=KIND_PARAM,
            meta={
                "any_of": list(GODZILLA_PARAMS),
                "value_regex": r"^[A-Za-z0-9+/=%.]{32,}$",
            },
            advice="pass/key 是哥斯拉默认的载荷与密钥参数名；若业务接口不使用该命名则风险很高。",
            tags=("webshell", "godzilla"),
        )
    )
    out.append(
        Rule(
            id="GOD-021",
            tool=TOOL,
            title="请求体为非 Base64 的原始二进制乱码（哥斯拉原始载荷模式）",
            score=25,
            kind=KIND_ENTROPY,
            fields=("body",),
            meta={
                "min_len": 48,
                "min_entropy": 5.5,
                "forbid_printable_ratio": 0.92,
                "require_content_type": ["application/octet-stream", "application/x-www-form-urlencoded"],
            },
            advice="哥斯拉可选择直接投递二进制载荷，请结合 Content-Type 与响应结构判定。",
            tags=("webshell", "godzilla", "载荷形态"),
        )
    )

    # --- JSP 反射链 ------------------------------------------------------
    out.append(
        Rule(
            id="GOD-030",
            tool=TOOL,
            title="载荷/响应命中 Java 反射与类加载链（ClassLoader/defineClass/PageContext）",
            score=45,
            kind=KIND_REGEX,
            pattern=JAVA_REFLECTION,
            fields=("body", "params", "response", "all"),
            flags="i",
            advice="哥斯拉 JSP 型通过 Java 反射加载攻击者 payload，属内存马特征。",
            tags=("webshell", "godzilla", "jsp", "内存马"),
        )
    )
    out.append(
        Rule(
            id="GOD-031",
            tool=TOOL,
            title="载荷含 xc/pass 参数与 Base64 编解码函数组合",
            score=35,
            kind=KIND_META,
            meta={
                "param_any": ["xc", "pass"],
                "regex_any": [r"Base64|base64Decode|decodeBuffer|new\s+sun\.misc", r"getInputStream|readLine"],
            },
            advice="xc + pass 是哥斯拉 JSP 载荷的默认参数组合。",
            tags=("webshell", "godzilla", "jsp"),
        )
    )

    # --- 行为特征 --------------------------------------------------------
    out.append(
        Rule(
            id="GOD-040",
            tool=TOOL,
            title="同一路径高频等长 POST 且每次响应长度一致（心跳式 C2 通信）",
            score=25,
            kind=KIND_ENTROPY,
            fields=("flow",),
            meta={"min_requests": 5, "window_sec": 120, "uniform_body_len": True},
            advice="管理端会以固定周期轮询被控端，形成长度高度一致的请求/响应序列。",
            tags=("webshell", "godzilla", "行为特征"),
        )
    )
    out.append(
        Rule(
            id="GOD-041",
            tool=TOOL,
            title="XMLHttpRequest 头存在但缺少浏览器常规伴随头（Host 位置异常）",
            score=15,
            kind=KIND_META,
            meta={
                "header_all": [{"header": "x-requested-with", "contains": "XMLHttpRequest"}],
                "require_not": [{"header": "origin"}, {"header": "referer"}],
                "min_headers": 4,
            },
            advice=(
                "哥斯拉/冰蝎的请求头顺序与浏览器不同（Host 常排在 UA、Accept 之后），"
                "配合缺失 Origin/Referer 可作为辅助判定。"
            ),
            tags=("webshell", "弱特征"),
        )
    )

    # --- 元规则 ----------------------------------------------------------
    out.append(
        Rule(
            id="GOD-090",
            tool=TOOL,
            title="多信号聚合判定为哥斯拉会话（畸形 Cookie + 加密载荷 + 响应结构）",
            score=50,
            kind=KIND_META,
            meta={
                "require_any": ["GOD-013", "GOD-010", "GOD-001"],
                "also_any": ["GOD-002", "GOD-020", "GOD-021", "GOD-030", "GOD-012"],
            },
            advice="多个独立信号共同命中，建议按入侵事件处置：隔离主机、下线 webshell、排查横向移动。",
            tags=("webshell", "godzilla", "聚合"),
        )
    )
    return out
