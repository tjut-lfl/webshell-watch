"""
通用规则：TLS/协议层指纹，以及不属于单一工具的高危 webshell 特征。

这些规则承担两类职责：
  1. 当流量被 TLS 加密、看不到明文时，仅凭协议层指纹与“头部自相矛盾”给出判定
     （蚁剑/冰蝎/哥斯拉的 JSP 端跑在 Tomcat/Weblogic 上，TLS 栈是 JDK 或
       Java 库，而管理端 UA 却常伪装成浏览器 —— 这种矛盾是强信号）；
  2. 兜底的通用 webshell 行为特征，用于识别魔改版本、自研管理端或菜刀类工具。
"""

from __future__ import annotations

from .rules import Rule, KIND_ENTROPY, KIND_HEADER, KIND_META, KIND_REGEX, KIND_TLS

TOOL_TLS = "加密隧道"
TOOL_GENERIC = "通用WebShell"


def rules() -> list[Rule]:
    out: list[Rule] = []

    # =====================================================================
    # TLS 层
    # =====================================================================
    out.append(
        Rule(
            id="TLS-001",
            tool=TOOL_TLS,
            title="TLS 客户端为 JDK/JSSE 栈，但 User-Agent 声称是浏览器（身份矛盾）",
            score=60,
            kind=KIND_TLS,
            meta={"client_kind": "java", "ua_not_browser": True},
            advice=(
                "管理端用 Java 发起 TLS，却把 User-Agent 伪装成 Chrome/Firefox。"
                "真实浏览器不会出现这种组合，强烈提示冰蝎/哥斯拉等 Java 客户端在通信。"
                "请对目的 IP 做流量留存并检查对应业务主机是否存在 JSP 马。"
            ),
            tags=("webshell", "tls", "矛盾特征"),
        )
    )
    out.append(
        Rule(
            id="TLS-002",
            tool=TOOL_TLS,
            title="TLS 客户端为编程语言 TLS 库（OpenSSL/Go/Python/curl）",
            score=35,
            kind=KIND_TLS,
            meta={"client_kind": "runtime"},
            advice=(
                "该会话由程序化客户端发起而非浏览器。若同一客户端还在短时间内访问大量不同主机，"
                "或访问路径与业务无关（如 /upload/*.jsp），应重点核查。"
            ),
            tags=("webshell", "tls", "客户端指纹"),
        )
    )
    out.append(
        Rule(
            id="TLS-003",
            tool=TOOL_TLS,
            title="ClientHello 提供极少的密码套件/扩展（自动化工具栈特征）",
            score=20,
            kind=KIND_TLS,
            meta={"max_ciphers": 12, "max_extensions": 10, "no_alpn": True},
            advice="浏览器 ClientHello 通常有 15+ 密码套件与 ALPN h2/http1.1，异常精简的握手来自工具库。",
            tags=("webshell", "tls", "弱特征"),
        )
    )
    out.append(
        Rule(
            id="TLS-004",
            tool=TOOL_TLS,
            title="JA3 命中已知非浏览器指纹库",
            score=25,
            kind=KIND_TLS,
            meta={"known_non_browser": True, "any_known": True},
            advice="JA3 指纹命中公开指纹库中的 Java/OpenSSL 条目，可作为加密流量分析的辅助证据。",
            tags=("webshell", "tls", "指纹库"),
        )
    )
    out.append(
        Rule(
            id="TLS-005",
            tool=TOOL_TLS,
            title="TLS 客户端只声明 http/1.1（ALPN 单值，程序化客户端特征）",
            score=20,
            kind=KIND_TLS,
            meta={"alpn_exact": ["http/1.1"]},
            advice=(
                "现代浏览器在 TLS 握手中会同时声明 h2 与 http/1.1；"
                "只声明 http/1.1 说明是程序化的 HTTP 客户端（HTTP 客户端库、脚本、"
                "webshell 管理端常见）。属弱特征，建议与访问频率、路径特征联合判定。"
            ),
            tags=("webshell", "tls", "弱特征"),
        )
    )

    # =====================================================================
    # 通用 webshell 行为
    # =====================================================================
    out.append(
        Rule(
            id="GEN-001",
            tool=TOOL_GENERIC,
            title="请求参数中包含系统命令执行调用（whoami/cmd.exe//bin/sh 等）",
            score=50,
            kind=KIND_REGEX,
            pattern=(
                r"(?:cmd(?:\.exe)?\s*/c\s|/bin/(?:ba)?sh\s+-c|powershell(?:\.exe)?\s+-|"
                r"whoami\b|net\s+user\b|ipconfig\b|systeminfo\b|/etc/passwd|"
                r"cat\s+/etc/|id\s*;|uname\s+-a)"
            ),
            fields=("body", "params", "url"),
            flags="i",
            advice="请求中直接携带操作系统命令，属命令执行类 webshell 调用；请确认该接口是否本应接受此类输入。",
            tags=("webshell", "命令执行", "通用"),
        )
    )
    out.append(
        Rule(
            id="GEN-002",
            tool=TOOL_GENERIC,
            title="请求参数中出现 Base64 编码的 PHP/Java/.NET 代码",
            score=45,
            kind=KIND_REGEX,
            pattern=(
                r"(?:PD9waHA|PD9waH|QGV2YWw|ZXZhbCg|c3lzdGVt|YXNzZXJ0|"
                r"cGhwaW5mby|Y2xhc3MgVXxpbXBvcnQgamF2YQ|cGFja2FnZSB8"
                r"U3lzdGVtXC5SZWZsZWN0aW9u)"
            ),
            fields=("body", "params", "url"),
            advice=(
                "这些 Base64 片段解码后为 <?php / eval( / system( / class U / import java 等代码开头，"
                "说明载荷是被编码的脚本代码。"
            ),
            tags=("webshell", "编码载荷", "通用"),
        )
    )
    out.append(
        Rule(
            id="GEN-003",
            tool=TOOL_GENERIC,
            title="POST 到脚本类路径且请求体为高熵密文（一句话木马通信形态）",
            score=20,
            kind=KIND_ENTROPY,
            fields=("body",),
            meta={
                "min_len": 64,
                "min_entropy": 5.0,
                "require_path_regex": r"\.(?:php|jsp|jspx|asp|aspx|ashx|do|action)\b",
                "require_method": ["POST"],
            },
            advice="脚本页面 + 高熵 POST 体是 webshell 数据通道的通用形态，建议与访问日志关联分析。",
            tags=("webshell", "行为特征", "通用"),
        )
    )
    out.append(
        Rule(
            id="GEN-004",
            tool=TOOL_GENERIC,
            title="探测性访问 webshell 常见路径名",
            score=15,
            kind=KIND_REGEX,
            pattern=(
                r"/(?:shell|cmd|hack|ma|muma|x\.jsp|1\.php|test\.php|upload|config|"
                r"admin|system|db|sql|backup|tmp)[^/]*\.(?:php|jsp|jspx|asp|aspx|ashx)\b"
            ),
            fields=("url",),
            flags="i",
            advice="路径命名与业务无关且命中常见 webshell 命名习惯，属弱特征，需结合其它信号确认。",
            tags=("webshell", "弱特征", "通用"),
        )
    )
    out.append(
        Rule(
            id="GEN-005",
            tool=TOOL_GENERIC,
            title="请求头顺序异常（Host 排在 User-Agent/Accept 之后）",
            score=10,
            kind=KIND_META,
            meta={"host_order_after": 2, "min_headers": 5},
            advice=(
                "正常浏览器与反向代理都会把 Host 放在请求行之后的第一位；"
                "Host 后置说明是程序拼装的请求，属辅助特征。"
            ),
            tags=("webshell", "弱特征", "通用"),
        )
    )
    out.append(
        Rule(
            id="GEN-006",
            tool=TOOL_GENERIC,
            title="请求体含 PHP 一句话马特征前缀（$_POST/$_REQUEST 变量读取）",
            score=30,
            kind=KIND_REGEX,
            pattern=r"\$_(?:POST|REQUEST|GET)\s*\[|assert\s*\(\$|@?\$_(?:POST|REQUEST)\s*\[",
            fields=("body", "params"),
            advice="载荷在服务端直接读取 POST/REQUEST 参数并执行，是一句话木马的核心形态。",
            tags=("webshell", "php", "通用"),
        )
    )
    out.append(
        Rule(
            id="GEN-007",
            tool=TOOL_GENERIC,
            title="Cookie 以分号结尾（工具生成的畸形 Cookie，浏览器不会这样发）",
            score=15,
            kind=KIND_HEADER,
            meta={"header": "cookie", "regex": r";\s*$"},
            advice=(
                "哥斯拉/冰蝎等管理端拼接 Cookie 时会多出一个分号，浏览器不会产生这种形态。"
                "属弱特征，单独不足以定性，请与同会话的其它特征联合判定。"
            ),
            tags=("webshell", "弱特征", "通用"),
        )
    )
    return out
