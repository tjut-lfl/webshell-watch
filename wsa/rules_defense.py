"""
防守端规则：面向「服务器被 webshell 远控」这一防御场景。

与攻击工具特征规则（蚁剑/冰蝎/哥斯拉）的区别：
    攻击工具规则看的是「请求长什么样」，命中即可定性；
    防守端规则看的是「服务器的日志与文件里出现了什么异常」，
    多数属于行为/统计特征，单独一条往往不足以定性，
    因此分值刻意压得较低，依赖与工具特征规则叠加后才升级为高危。

规则类型（kind）说明：
    log     日志字段条件（状态码、方法、路径、Referer、UA 等组合）
    stat    统计/行为条件（同源高频、失败次数等），由对应监控器提供上下文
    filescan 文件内容特征（静态扫描命中的 webshell 代码片段）
    filemeta 文件元信息条件（新增脚本、权限异常、时间异常）
    policy  配置基线问题（例如没有开启请求体日志，会影响检测能力）
"""

from __future__ import annotations

from .rules import Rule

TOOL = "防守告警"

KIND_LOG = "log"
KIND_STAT = "stat"
KIND_FILESCAN = "filescan"
KIND_FILEMETA = "filemeta"
KIND_POLICY = "policy"


def rules() -> list[Rule]:
    out: list[Rule] = []

    # =====================================================================
    # 1. 日志侧：脚本文件的异常访问（webshell 调用形态）
    # =====================================================================
    out.append(
        Rule(
            id="DEF-001",
            tool=TOOL,
            title="POST 访问脚本文件且带载荷体、缺少 Referer（典型 webshell 调用）",
            score=25,
            kind=KIND_LOG,
            meta={
                "require_method": ["POST"],
                "require_path_ext": [".php", ".jsp", ".jspx", ".asp", ".aspx", ".ashx", ".phtml", ".phar"],
                "require_body_min": 16,
                "require_missing_header": ["referer"],
                "require_status": [200, 500, 502],
            },
            advice=(
                "正常业务表单提交通常带 Referer 与多个参数；"
                "单个 POST 直接打向脚本文件、体内是大段编码数据且无来源页，"
                "符合一句话木马被调用的形态。请核对该文件是否为业务文件，"
                "并用文件巡检结果交叉确认。"
            ),
            tags=("webshell", "日志特征"),
        )
    )
    out.append(
        Rule(
            id="DEF-002",
            tool=TOOL,
            title="请求体为「参数名 + Base64/URL 编码大块数据」的单参数结构",
            score=20,
            kind=KIND_LOG,
            meta={
                "require_method": ["POST"],
                "require_path_ext": [".php", ".jsp", ".jspx", ".asp", ".aspx", ".ashx"],
                "require_body_min": 48,
                "require_single_param": True,
                "require_body_base64ish": True,
            },
            advice="单参数承载编码载荷是 webshell 管理端的通用数据通道形态。",
            tags=("webshell", "日志特征"),
        )
    )
    out.append(
        Rule(
            id="DEF-003",
            tool=TOOL,
            title="请求路径命中 webshell 常见命名但请求为 200",
            score=15,
            kind=KIND_LOG,
            meta={
                "require_status": [200],
                "require_path_regex": (
                    r"/(?:shell|cmd|hack|muma|webshell|backdoor|xiaoma|1|2|test|tmp|upload|"
                    r"conf|config|db|sql|admin|system|info|phpinfo)[^/]*"
                    r"\.(?:php|jsp|jspx|asp|aspx|ashx|phtml)\b"
                ),
            },
            advice="路径命名与业务无关且命中常见 webshell 习惯，属弱特征，需与其它信号共同判定。",
            tags=("webshell", "弱特征"),
        )
    )
    out.append(
        Rule(
            id="DEF-004",
            tool=TOOL,
            title="对不存在的脚本文件的 POST 探测（404/403 + 编码体）",
            score=12,
            kind=KIND_LOG,
            meta={
                "require_method": ["POST"],
                "require_status": [404, 403, 401],
                "require_path_ext": [".php", ".jsp", ".asp", ".aspx", ".ashx"],
            },
            advice="攻击者常先探测马文件是否存在；连续出现请关注同源 IP 的其它请求。",
            tags=("webshell", "探测", "弱特征"),
        )
    )

    # =====================================================================
    # 2. 日志侧：扫描器与已知恶意工具
    # =====================================================================
    out.append(
        Rule(
            id="DEF-010",
            tool=TOOL,
            title="已知 webshell 扫描器 / 利用工具的 User-Agent",
            score=35,
            kind=KIND_LOG,
            meta={
                "require_ua_regex": (
                    r"(?:antSword|Behinder|behinder|Godzilla|godzilla|ChinaChopper|chopper|"
                    r"webshell[-_ ]?killer|WSC|WVS|wvs|Acunetix|Netsparker|nikto|sqlmap|"
                    r"Nuclei|nuclei|Xray|xray|Goby|goby|dirsearch|gobuster|feroxbuster|"
                    r"masscan|zmap|fscan|afrog|Yakit|BurpSuite|python-requests|Go-http-client|"
                    r"okhttp|Java/\d|curl/)"
                )
            },
            advice=(
                "该 UA 属于 webshell 管理工具或自动化扫描器。若来源不是授权扫描的 IP，"
                "应视为攻击行为；请结合同源 IP 的完整请求序列研判。"
            ),
            tags=("扫描器", "恶意UA"),
        )
    )
    out.append(
        Rule(
            id="DEF-011",
            tool=TOOL,
            title="请求体/URL 命中常见 webshell 利用与命令执行载荷",
            score=30,
            kind=KIND_LOG,
            meta={
                "require_regex": (
                    r"(?:\b(?:eval|assert|system|exec|passthru|shell_exec|popen|proc_open)\s*\(|"
                    r"base64_decode\s*\(|gzinflate\s*\(|str_rot13\s*\(|create_function\s*\(|"
                    r"\$_POST\s*\[|\$_REQUEST\s*\[|\$_GET\s*\[|"
                    r"Runtime\.getRuntime|ProcessBuilder|ClassLoader|defineClass|"
                    r"Assembly\.Load|CSharpCodeProvider|"
                    r"whoami|/etc/passwd|cmd\.exe|/bin/sh\s+-c|powershell\s+-|"
                    r"\.\./\.\./|%2e%2e%2f|php://input|data://|phar://)"
                )
            },
            advice=(
                "请求里出现代码执行函数、敏感文件路径或穿越序列，"
                "通常是一次 webshell 利用尝试或漏洞利用。请立即核对响应状态码与服务器是否存在对应文件。"
            ),
            tags=("命令执行", "漏洞利用"),
        )
    )
    out.append(
        Rule(
            id="DEF-012",
            tool=TOOL,
            title="命中常见上传/包含漏洞利用路径",
            score=20,
            kind=KIND_LOG,
            meta={
                "require_regex": (
                    r"(?:/upload(?:file)?\.(?:php|jsp|asp|aspx)|/fileupload|/fckeditor|/ueditor|"
                    r"/kindeditor|/ewebeditor|/phpmyadmin|/manager/html|/solr/admin|"
                    r"/actuator|/console|/druid|/weblogic|/struts|/seeyon|/nexus)"
                )
            },
            advice="这些是常见漏洞入口与后台路径。若非运维主动访问，请重点核查。",
            tags=("漏洞利用", "弱特征"),
        )
    )

    # =====================================================================
    # 3. 统计与行为
    # =====================================================================
    out.append(
        Rule(
            id="DEF-020",
            tool=TOOL,
            title="同源 IP 短时间内高频请求脚本文件（webshell 交互或爆破）",
            score=20,
            kind=KIND_STAT,
            meta={"counter": "same_ip_to_script", "window": 60, "threshold": 30},
            advice="管理端命令执行会在短时间内产生大量请求。请查看该 IP 的请求路径与载荷，确认是否为业务接口。",
            tags=("行为特征", "高频"),
        )
    )
    out.append(
        Rule(
            id="DEF-021",
            tool=TOOL,
            title="同一脚本文件被大量不同 IP 访问（马文件已被批量利用）",
            score=25,
            kind=KIND_STAT,
            meta={"counter": "script_multi_ip", "window": 300, "threshold": 8},
            advice="正常业务文件很少被大量互不相关的 IP 以 POST 方式访问。请立即检查该文件内容。",
            tags=("行为特征", "多源"),
        )
    )

    # =====================================================================
    # 4. 文件侧
    # =====================================================================
    out.append(
        Rule(
            id="DEF-030",
            tool=TOOL,
            title="Web 目录出现新增脚本文件",
            score=30,
            kind=KIND_FILEMETA,
            meta={"event": "new_file"},
            advice=(
                "Web 目录新增脚本文件本身不一定是攻击（也可能是正常发布），"
                "但如果它不是通过发布流程产生、且内容命中 webshell 特征，应立即隔离。"
                "请核对文件时间、属主与内容。"
            ),
            tags=("文件", "新增"),
        )
    )
    out.append(
        Rule(
            id="DEF-031",
            tool=TOOL,
            title="脚本文件内容命中 webshell 静态特征",
            score=55,
            kind=KIND_FILESCAN,
            meta={"scanner": "webshell_signature"},
            advice=(
                "文件内容包含一句话木马/加密马的典型结构（动态执行函数 + 变量传参）。"
                "请立即隔离该文件（先改权限或改名），保存样本，再排查它是怎么上传进来的。"
            ),
            tags=("文件", "webshell", "强特征"),
        )
    )
    out.append(
        Rule(
            id="DEF-032",
            tool=TOOL,
            title="脚本文件内容命中编码/混淆型 webshell 特征",
            score=45,
            kind=KIND_FILESCAN,
            meta={"scanner": "obfuscated_webshell"},
            advice="文件包含大段编码数据配合解码执行函数，属混淆马。请用工具展示的片段人工确认后隔离。",
            tags=("文件", "webshell", "混淆"),
        )
    )
    out.append(
        Rule(
            id="DEF-033",
            tool=TOOL,
            title="脚本文件权限异常（全局可写 or 属主为 Web 进程用户）",
            score=20,
            kind=KIND_FILEMETA,
            meta={"event": "bad_mode"},
            advice=(
                "Web 目录下的脚本文件如果是 777 或属主为 www-data/nginx/apache，"
                "说明可被 Web 进程直接改写，攻击者可借此植入或篡改代码。"
                "建议属主改为 root:root，权限 644。"
            ),
            tags=("文件", "权限加固"),
        )
    )
    out.append(
        Rule(
            id="DEF-034",
            tool=TOOL,
            title="脚本文件被修改（内容哈希与基线不一致）",
            score=25,
            kind=KIND_FILEMETA,
            meta={"event": "modified_file"},
            advice=(
                "已建立基线的文件内容发生变化。若是正常发布请更新基线；"
                "否则请对比差异，确认是否被插入了后门代码。"
            ),
            tags=("文件", "篡改"),
        )
    )

    out.append(
        Rule(
            id="DEF-035",
            tool=TOOL,
            title="Web 目录下出现非 Web 脚本文件（.py/.pl/.sh/.cgi/.war）",
            score=30,
            kind=KIND_FILEMETA,
            meta={"event": "odd_script"},
            advice=(
                "Web 目录里通常只放 .php/.jsp/.html 这类文件。"
                ".py/.pl/.sh/.cgi/.war 出现往往意味着攻击者上传了可执行脚本，"
                "或借助此类文件反弹 shell（CGI 执行、war 包自动部署都是常见手法）。"
                "请确认来源，不是业务需要就立即删除并排查上传途径。"
            ),
            tags=("文件", "可疑类型", "强特征"),
        )
    )

    out.append(
        Rule(
            id="DEF-036",
            tool=TOOL,
            title="上传目录中出现脚本文件（.aspx/.php/.jsp 等）",
            score=35,
            kind=KIND_FILEMETA,
            meta={"event": "script_in_upload_dir"},
            advice=(
                "上传目录（upload/files/attachment/media/temp 等）本应只放数据文件。"
                "出现脚本文件几乎只有两种可能：攻击者上传了马，或业务把可执行内容"
                "放进了可写目录。请立即核对来源，并禁止该目录执行脚本。"
            ),
            tags=("文件", "上传", "强特征"),
        )
    )

    out.append(
        Rule(
            id="DEF-037",
            tool=TOOL,
            title="Windows 临时/公共目录出现新的可执行文件（装载器、挖矿、工具落地）",
            score=40,
            kind=KIND_FILEMETA,
            meta={"event": "suspicious_path_executable"},
            advice=(
                "C:\\Windows\\Temp、C:\\Users\\Public、C:\\ProgramData、计划任务目录等位置"
                "是 Windows 上最常见的工具落地处。webshell 拿到执行权限后通常"
                "会往这些目录下载 cs/msf 的 exe、dll 或挖矿程序。"
                "请把文件样本（哈希 + 路径）留存后隔离主机。"
            ),
            tags=("文件", "windows", "落地", "强特征"),
        )
    )

    out.append(
        Rule(
            id="DEF-038",
            tool=TOOL,
            title="Web 目录下出现新的 Web.config / .user.ini / .htaccess",
            score=40,
            kind=KIND_FILEMETA,
            meta={"event": "web_config_modified"},
            advice=(
                "攻击者常通过改写 Web 配置实现持久化或提权："
                "IIS 的 web.config 可添加处理程序映射让图片当脚本执行；"
                "PHP 的 .user.ini 可设置 auto_prepend_file 让每个请求先执行马；"
                ".htaccess 可开启 AllowOverride 后的任意指令。"
                "请对比配置文件内容，确认是否被插入恶意映射。"
            ),
            tags=("文件", "持久化", "强特征"),
        )
    )

    # =====================================================================
    # 5. 认证侧
    # =====================================================================
    out.append(
        Rule(
            id="DEF-040",
            tool=TOOL,
            title="SSH 暴力破解（同源 IP 在窗口内多次认证失败）",
            score=30,
            kind=KIND_STAT,
            meta={"source": "auth", "counter": "ssh_fail", "window": 300, "threshold": 10},
            advice=(
                "同源 IP 反复认证失败是典型的密码爆破。建议："
                "限制该 IP（nftables/ufw）、关闭密码登录改用密钥、检查是否有成功登录记录"
                "（成功登录会单独告警）。"
            ),
            tags=("认证", "爆破"),
        )
    )
    out.append(
        Rule(
            id="DEF-041",
            tool=TOOL,
            title="SSH 认证成功（需与来源是否为可信 IP 交叉确认）",
            score=15,
            kind=KIND_STAT,
            meta={"source": "auth", "counter": "ssh_success"},
            advice=(
                "服务器登录成功事件。若来源 IP 不在你的运维白名单内，"
                "请立即确认是否为入侵者登录，并检查该会话执行过的命令与新建文件。"
            ),
            tags=("认证", "登录"),
        )
    )
    out.append(
        Rule(
            id="DEF-042",
            tool=TOOL,
            title="提权或敏感操作（sudo/SU 成功、新用户创建、SSH 密钥被追加）",
            score=40,
            kind=KIND_STAT,
            meta={"source": "auth", "counter": "privilege_event"},
            advice=(
                "检测到提权或账号变更操作，这是 webshell 落地后横向移动与持久化的关键动作。"
                "请立即核对 ~/.ssh/authorized_keys、/etc/passwd、/etc/sudoers 的最近改动。"
            ),
            tags=("认证", "提权", "持久化"),
        )
    )
    out.append(
        Rule(
            id="DEF-043",
            tool=TOOL,
            title="Windows 新服务被安装（攻击者常用持久化手法）",
            score=45,
            kind=KIND_STAT,
            meta={"source": "winevent", "counter": "win_service_install", "event_id": 7045},
            advice=(
                "在 Windows 上安装服务是攻击者最常用的持久化方式之一"
                "（sc create / 服务型木马 / PsExec 都会产生 7045 事件）。"
                "请核对该服务的可执行路径：如果指向 Temp、Public、ProgramData 等"
                "非标准目录，基本可以确认是攻击者留下的。处置：停服务 → 留存 exe 样本 → 删除服务。"
            ),
            tags=("windows", "持久化", "服务", "强特征"),
        )
    )
    out.append(
        Rule(
            id="DEF-044",
            tool=TOOL,
            title="PowerShell 脚本块包含下载执行/绕过防护等高危内容",
            score=45,
            kind=KIND_STAT,
            meta={"source": "winevent", "counter": "win_ps_scriptblock", "event_id": 4104},
            advice=(
                "脚本块里出现 IEX、DownloadString、FromBase64String、-EncodedCommand、"
                "或修改 Defender 排除项等关键字，是典型的「webshell 落地后下载工具」行为。"
                "请注意 4104 需要开启 PowerShell 脚本块日志（默认可能未开），"
                "开启方式见 README 的 Windows 章节。"
            ),
            tags=("windows", "powershell", "强特征"),
        )
    )

    # =====================================================================
    # 6. 配置与能力基线（提醒，不是攻击）
    # =====================================================================
    out.append(
        Rule(
            id="DEF-050",
            tool=TOOL,
            title="Web 日志未记录请求体，检测能力受限",
            score=10,
            kind=KIND_POLICY,
            meta={"policy": "no_request_body"},
            advice=(
                "当前日志里看不到 POST 请求体，只能依靠 URL/UA/状态码与文件巡检判定，"
                "对加密马（冰蝎/哥斯拉）几乎无能为力。"
                "建议在 nginx 中加入 log_format 与 $request_body（见 README 第 3 节），"
                "或在无法改配置时改为对明文 HTTP 启用抓包监控。"
            ),
            tags=("配置", "能力基线"),
        )
    )
    out.append(
        Rule(
            id="DEF-051",
            tool=TOOL,
            title="Web 目录巡检权限不足，部分目录无法读取",
            score=10,
            kind=KIND_POLICY,
            meta={"policy": "unreadable_webroot"},
            advice=(
                "巡检进程读不到部分 Web 目录，可能存在漏检。"
                "建议给服务账号补上读权限，或改为 root 运行巡检。"
            ),
            tags=("配置", "能力基线"),
        )
    )
    return out
