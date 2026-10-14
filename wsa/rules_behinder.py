"""
冰蝎（Behinder 2.0 / 3.0 / 4.0）流量特征规则。

依据（公开源码与流量研究归纳）：
  * 2.0：AES-CBC + Base64，密钥动态协商（首次请求返回 16 位随机 key 的 MD5）
  * 3.0：AES-128 + Base64，密钥 = 连接密码 32 位 MD5 的前 16 位
        默认密码 rebeyond → 默认密钥 e45e329feb5d925b
  * 4.0：保留默认密钥；Accept 常见 application/json, text/javascript, */*; q=0.01
        连接 PHP 时 Content-Type: application/x-www-form-urlencoded
        连接 JSP/ASPX 时 Content-Type: application/octet-stream（弱特征）
  * 内置十几个真实浏览器 User-Agent 随机挑选（Mac Chrome 89 / Firefox 87 等）
  * 4.0 使用长连接 Connection: Keep-Alive，本地端口常在 49700 附近递增
  * 4.0 默认密钥下请求/响应存在固定字节头：
        请求 dFAXQV1LORcHRQtLRlwMAhwFTAg/M
        响应 TxcWR1NNExZAD0ZaAWMIPAZjH1BFBFtHTHcJSlUXWEd
  * JSP 马：ClassLoader.defineClass 动态加载字节码，AES 解密后的 class 魔数 cafe babe
"""

from __future__ import annotations

from .rules import Rule, KIND_ENTROPY, KIND_HEADER, KIND_META, KIND_PARAM, KIND_REGEX, KIND_SUBSTR

TOOL = "冰蝎"

#: 3.0/4.0 默认密钥（连接密码 rebeyond 的 MD5 前 16 位）
DEFAULT_KEY = "e45e329feb5d925b"

#: 4.0 默认密钥下的固定请求/响应字节头（Go 风格 Base64；此处为对外可见形态）
FIXED_REQ_HEADER = "dFAXQV1LORcHRQtLRlwMAhwFTAg/M"
FIXED_RESP_HEADER = "TxcWR1NNExZAD0ZaAWMIPAZjH1BFBFtHTHcJSlUXWEd"

#: 内置 UA 池中具有版本聚焦特征的条目（冰蝎 3.x/4.x 编译进客户端的字符串）
UA_POOL_MARKERS = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_2_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.114 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:87.0) Gecko/20100101 Firefox/87.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.125 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.125 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.125 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.125 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:79.0) Gecko/20100101 Firefox/79.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:79.0) Gecko/20100101 Firefox/79.0",
    "Mozilla/5.0 (Linux x86_64; rv:79.0) Gecko/20100101 Firefox/79.0",
)

#: 冰蝎 initHeaders() 里固定的 Accept / Accept-Language / Accept-Encoding
BEHINDER_ACCEPT = (
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,"
    "application/signed-exchange;v=b3;q=0.9"
)
BEHINDER_ACCEPT_LANG = "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7"
BEHINDER_ACCEPT_40 = "application/json, text/javascript, */*; q=0.01"

#: Java 序列化魔数（Base64 解码后出现即高度可疑）
JAVA_SER_MAGIC_B64 = "rO0AB"


def rules() -> list[Rule]:
    out: list[Rule] = []

    # --- 客户端指纹 -------------------------------------------------------
    out.append(
        Rule(
            id="BEH-001",
            tool=TOOL,
            title="User-Agent 命中冰蝎内置 UA 池（Chrome 89 / Firefox 87 等固定版本组合）",
            score=45,
            kind=KIND_HEADER,
            meta={"header": "user-agent", "equals_any": list(UA_POOL_MARKERS)},
            advice=(
                "冰蝎客户端从编译进程序的一组 UA 中随机挑选，这些字符串与常见浏览器版本强绑定。"
                "请结合请求频率（每秒多次 POST）、URL 是否为一句话木马路径综合判断。"
            ),
            tags=("webshell", "behinder", "客户端指纹"),
        )
    )
    out.append(
        Rule(
            id="BEH-002",
            tool=TOOL,
            title="冰蝎默认头部组合（Accept-Encoding: gzip, deflate, br + 固定 Accept/Accept-Language）",
            score=40,
            kind=KIND_META,
            meta={
                "header_all": [
                    {"header": "accept-encoding", "contains": "gzip, deflate, br"},
                    {"header": "accept-language", "contains": BEHINDER_ACCEPT_LANG},
                    {"header": "accept", "contains": "application/signed-exchange;v=b3"},
                ],
                "require_not": [{"header": "sec-fetch-mode"}],
            },
            advice=(
                "该三件套来自冰蝎 initHeaders()，而真实浏览器请求几乎必然带 sec-fetch-* 头部。"
                "缺少 sec-fetch-* 却携带上述组合，是自动化客户端的典型矛盾。"
            ),
            tags=("webshell", "behinder", "头部指纹"),
        )
    )
    out.append(
        Rule(
            id="BEH-003",
            tool=TOOL,
            title="冰蝎 4.0 请求特征：Accept 为 application/json, text/javascript, */*; q=0.01",
            score=25,
            kind=KIND_HEADER,
            meta={"header": "accept", "contains": BEHINDER_ACCEPT_40},
            advice="弱特征，需与加密载荷、请求频率等信号联合判定。",
            tags=("webshell", "behinder", "弱特征"),
        )
    )

    # --- 固定密钥痕迹 -----------------------------------------------------
    out.append(
        Rule(
            id="BEH-010",
            tool=TOOL,
            title="流量中出现冰蝎默认密钥（e45e329feb5d925b）",
            score=60,
            kind=KIND_SUBSTR,
            pattern=DEFAULT_KEY,
            fields=("all",),
            advice=(
                "e45e329feb5d925b 是连接密码 rebeyond 的 MD5 前 16 位，即冰蝎 3.x/4.x 默认 AES 密钥。"
                "明文出现说明服务端马文件或客户端配置被捕获，请立即下线该 webshell 并轮换口令。"
            ),
            tags=("webshell", "behinder", "强特征"),
        )
    )
    out.append(
        Rule(
            id="BEH-011",
            tool=TOOL,
            title="命中冰蝎默认密钥下的固定请求/响应字节头",
            score=55,
            kind=KIND_SUBSTR,
            pattern=FIXED_REQ_HEADER,
            fields=("all",),
            advice="该固定字节头仅在冰蝎使用默认密钥时出现，属于高置信度特征。",
            tags=("webshell", "behinder", "强特征"),
        )
    )
    out.append(
        Rule(
            id="BEH-012",
            tool=TOOL,
            title="命中冰蝎默认密钥下的固定响应字节头",
            score=55,
            kind=KIND_SUBSTR,
            pattern=FIXED_RESP_HEADER,
            fields=("response", "all"),
            advice="服务端返回的固定字节头，说明被控端马文件使用默认密钥通信。",
            tags=("webshell", "behinder", "强特征"),
        )
    )

    # --- 传输形态 --------------------------------------------------------
    out.append(
        Rule(
            id="BEH-020",
            tool=TOOL,
            title="JSP 型冰蝎：Content-Type: application/octet-stream 的 POST 且体为超长 Base64 密文",
            score=45,
            kind=KIND_META,
            meta={
                "header_all": [{"header": "content-type", "contains": "application/octet-stream"}],
                "require_body_base64": True,
                "min_body": 64,
            },
            advice=(
                "冰蝎连接 JSP/ASPX 马时以 application/octet-stream 投递原始加密字节流，"
                "正常 Web 业务的 POST 极少使用该 Content-Type。"
            ),
            tags=("webshell", "behinder", "jsp"),
        )
    )
    out.append(
        Rule(
            id="BEH-021",
            tool=TOOL,
            title="响应体为高熵密文且长度固定（AES 分组特征）",
            score=30,
            kind=KIND_ENTROPY,
            fields=("response",),
            meta={
                "min_len": 32,
                "min_entropy": 5.0,
                "length_multiple": 4,
                "charset": "base64",
                "require_status": [200],
            },
            advice=(
                "冰蝎回包统一是 AES 密文的 Base64，长度呈 4 字节对齐且整体接近均匀分布。"
                "业务 JSON/HTML 响应不会呈现这种形态。"
            ),
            tags=("webshell", "behinder", "响应特征"),
        )
    )
    out.append(
        Rule(
            id="BEH-022",
            tool=TOOL,
            title="响应 Base64 解码后出现 Java 序列化魔数（rO0AB / 0xACED）",
            score=50,
            kind=KIND_REGEX,
            pattern=r"rO0AB|\xac\xed\x00\x05",
            fields=("response", "body"),
            advice="冰蝎/哥斯拉的 JSP 载荷会下发 Java 序列化对象，普通业务响应不应包含。",
            tags=("webshell", "java", "通用"),
        )
    )

    # --- JSP 行为链 ------------------------------------------------------
    out.append(
        Rule(
            id="BEH-030",
            tool=TOOL,
            title="请求/响应中出现 ClassLoader.defineClass 动态加载字节码",
            score=50,
            kind=KIND_REGEX,
            pattern=(
                r"defineClass|ClassLoader|getClass\(\)\.getClassLoader|"
                r"java\.lang\.(?:Runtime|ProcessBuilder|ClassLoader)|"
                r"javax\.crypto\.spec|SecretKeySpec|Cipher\.getInstance"
            ),
            fields=("body", "params", "response", "all"),
            flags="i",
            advice=(
                "冰蝎 JSP 马通过 ClassLoader#defineClass 在内存中加载攻击者下发的 class，"
                "这是内存马与无文件落地的核心链路。"
            ),
            tags=("webshell", "behinder", "jsp", "内存马"),
        )
    )
    out.append(
        Rule(
            id="BEH-031",
            tool=TOOL,
            title="载荷中直接出现 Java class 魔数（cafebabe）",
            score=55,
            kind=KIND_REGEX,
            pattern=r"(?:\xca\xfe\xba\xbe|yv66vg)",
            fields=("body", "response", "binary"),
            advice="Base64 后的 class 文件固定以 yv66vg 开头，说明正在投递 Java 字节码到服务端执行。",
            tags=("webshell", "behinder", "jsp", "强特征"),
        )
    )

    # --- 参数与行为 ------------------------------------------------------
    out.append(
        Rule(
            id="BEH-040",
            tool=TOOL,
            title="单一参数承载超长随机密文（pass/自定义参数）",
            score=20,
            kind=KIND_PARAM,
            meta={
                "value_regex": r"^[A-Za-z0-9+/=]{64,}$",
                "max_params": 2,
                "entropy_min": 4.8,
            },
            advice="配合冰蝎头部特征与高频请求可判定为加密马通信。",
            tags=("webshell", "behinder", "行为特征"),
        )
    )
    # --- 元规则 ----------------------------------------------------------
    out.append(
        Rule(
            id="BEH-090",
            tool=TOOL,
            title="多信号聚合判定为冰蝎会话（客户端指纹 + 加密载荷 + 传输形态）",
            score=45,
            kind=KIND_META,
            meta={
                "require_any": ["BEH-001", "BEH-002", "BEH-020"],
                # 这里刻意不放 BEH-041：Cookie 尾分号是冰蝎/哥斯拉共有的弱特征，
                # 若算进来会让哥斯拉流量同时被判成冰蝎，造成归属混淆。
                "also_any": ["BEH-021", "BEH-040", "BEH-030", "BEH-003"],
            },
            advice="客户端指纹与加密载荷形态互相印证，误报概率低，建议按入侵事件处置并取证。",
            tags=("webshell", "behinder", "聚合"),
        )
    )
    return out
