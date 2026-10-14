"""
webshell-traffic-analyzer 核心包

一个纯标准库实现的 webshell 管理工具流量分析器，用于识别
蚁剑（AntSword）/ 冰蝎（Behinder）/ 哥斯拉（Godzilla）等工具的流量特征。

模块职责：
    models      领域模型（流、事务、告警、规则）
    pcap        PCAP/PCAPNG 解析
    capture     TCP 重组与 HTTP 事务装配
    http        HTTP 报文解析
    tls         TLS ClientHello 指纹（JA3）
    rules*      特征规则库
    analysis    检测引擎（打分与定性）
    evidence    加密载荷的验证性解密（取证）
    aes         纯 Python AES-128（供验证性解密使用）
    certca      自签 CA 与动态证书签发（供 HTTPS 中间人解密）
    proxy       内置 HTTP/HTTPS 分析代理
    sniff       原始套接字在线嗅探
    pcap_replay pcap 回放与目录监视
    alerts      告警落盘与控制台输出
    cli         命令行入口
    gui         tkinter 图形界面
"""

__version__ = "1.0.0"
__all__ = ["__version__"]
